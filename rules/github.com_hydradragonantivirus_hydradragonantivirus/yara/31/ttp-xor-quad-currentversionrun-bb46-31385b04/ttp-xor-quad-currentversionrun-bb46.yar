rule TTP_XOR_QUAD_CurrentVersionRun_bb46 {
  strings:
    $key_bb46 = { e8 29 [2] cc 27 [2] e7 0b [2] c9 29 [2] dd 32 [2] d2 28 [2] cc 35 [2] ce 34 [2] d5 32 [2] c9 35 [2] d5 1a }

  condition:
    any of them
}