rule TTP_XOR_QUAD_CurrentVersionRun_aa5e {
  strings:
    $key_aa5e = { f9 31 [2] dd 3f [2] f6 13 [2] d8 31 [2] cc 2a [2] c3 30 [2] dd 2d [2] df 2c [2] c4 2a [2] d8 2d [2] c4 02 }

  condition:
    any of them
}