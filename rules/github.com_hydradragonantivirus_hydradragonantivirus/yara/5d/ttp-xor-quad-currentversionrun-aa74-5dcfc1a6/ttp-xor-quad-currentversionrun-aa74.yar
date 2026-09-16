rule TTP_XOR_QUAD_CurrentVersionRun_aa74 {
  strings:
    $key_aa74 = { f9 1b [2] dd 15 [2] f6 39 [2] d8 1b [2] cc 00 [2] c3 1a [2] dd 07 [2] df 06 [2] c4 00 [2] d8 07 [2] c4 28 }

  condition:
    any of them
}