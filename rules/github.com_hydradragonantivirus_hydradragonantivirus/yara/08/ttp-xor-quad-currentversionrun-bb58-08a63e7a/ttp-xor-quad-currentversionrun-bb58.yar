rule TTP_XOR_QUAD_CurrentVersionRun_bb58 {
  strings:
    $key_bb58 = { e8 37 [2] cc 39 [2] e7 15 [2] c9 37 [2] dd 2c [2] d2 36 [2] cc 2b [2] ce 2a [2] d5 2c [2] c9 2b [2] d5 04 }

  condition:
    any of them
}