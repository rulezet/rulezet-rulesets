import "pe"
rule ASPack_v1_08_04 {
  strings:
    $a0 = { 60 E8 41 06 00 00 EB 41 }

  condition:
    $a0 at pe.entry_point
}