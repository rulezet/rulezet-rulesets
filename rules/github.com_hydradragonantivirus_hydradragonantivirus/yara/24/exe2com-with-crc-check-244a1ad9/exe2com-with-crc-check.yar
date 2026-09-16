import "pe"
rule _EXE2COM_With_CRC_check_ {
  meta:
    description = "EXE2COM (With CRC check)"

  strings:
    $0 = { B3 ?? B9 ?? ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 43 49 32 E4 03 D0 E3 }

  condition:
    $0 at pe.entry_point
}