rule TTP_XOR_QUAD_CurrentVersionRun_aa27 {
  strings:
    $key_aa27 = { f9 48 [2] dd 46 [2] f6 6a [2] d8 48 [2] cc 53 [2] c3 49 [2] dd 54 [2] df 55 [2] c4 53 [2] d8 54 [2] c4 7b }

  condition:
    any of them
}