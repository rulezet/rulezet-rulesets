import "pe"
rule WebCops_rule__DLL_____LINK_Data_Security {
  strings:
    $a0 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }

  condition:
    $a0 at pe.entry_point
}