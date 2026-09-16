import "pe"
rule Upack_Patch____Dwing {
  strings:
    $a0 = { 81 3A 00 00 00 02 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}