import "pe"
rule Dev_C___v4 {
  strings:
    $a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

  condition:
    $a0 at pe.entry_point
}