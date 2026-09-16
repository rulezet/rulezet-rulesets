import "pe"
rule MS_Visual_C___v_8_DLL__h_small_sig1_ {
  strings:
    $a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC }

  condition:
    $a0 at pe.entry_point
}