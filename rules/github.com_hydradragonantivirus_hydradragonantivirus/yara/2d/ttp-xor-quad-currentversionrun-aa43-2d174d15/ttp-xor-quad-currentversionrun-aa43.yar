rule TTP_XOR_QUAD_CurrentVersionRun_aa43 {
  strings:
    $key_aa43 = { f9 2c [2] dd 22 [2] f6 0e [2] d8 2c [2] cc 37 [2] c3 2d [2] dd 30 [2] df 31 [2] c4 37 [2] d8 30 [2] c4 1f }

  condition:
    any of them
}