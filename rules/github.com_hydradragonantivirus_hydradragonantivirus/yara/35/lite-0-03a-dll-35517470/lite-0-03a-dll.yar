import "pe"
rule Lite_0_03a_DLL {
  strings:
    $a0 = { 80 7C 24 08 01 75 F4 E9 ?? ?? FF FF 00 10 00 00 0C 00 00 00 06 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? ?? 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}