rule TTP_XOR_QUAD_CurrentVersionRun_aa69 {
  strings:
    $key_aa69 = { f9 06 [2] dd 08 [2] f6 24 [2] d8 06 [2] cc 1d [2] c3 07 [2] dd 1a [2] df 1b [2] c4 1d [2] d8 1a [2] c4 35 }

  condition:
    any of them
}