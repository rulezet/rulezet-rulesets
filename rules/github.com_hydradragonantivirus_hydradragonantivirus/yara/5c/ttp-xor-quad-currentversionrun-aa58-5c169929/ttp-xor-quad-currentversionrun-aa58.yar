rule TTP_XOR_QUAD_CurrentVersionRun_aa58 {
  strings:
    $key_aa58 = { f9 37 [2] dd 39 [2] f6 15 [2] d8 37 [2] cc 2c [2] c3 36 [2] dd 2b [2] df 2a [2] c4 2c [2] d8 2b [2] c4 04 }

  condition:
    any of them
}