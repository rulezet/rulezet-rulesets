rule TTP_XOR_QUAD_CurrentVersionRun_aa75 {
  strings:
    $key_aa75 = { f9 1a [2] dd 14 [2] f6 38 [2] d8 1a [2] cc 01 [2] c3 1b [2] dd 06 [2] df 07 [2] c4 01 [2] d8 06 [2] c4 29 }

  condition:
    any of them
}