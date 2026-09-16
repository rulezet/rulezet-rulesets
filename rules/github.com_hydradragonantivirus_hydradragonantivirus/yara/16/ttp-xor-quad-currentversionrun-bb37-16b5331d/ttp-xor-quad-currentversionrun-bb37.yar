rule TTP_XOR_QUAD_CurrentVersionRun_bb37 {
  strings:
    $key_bb37 = { e8 58 [2] cc 56 [2] e7 7a [2] c9 58 [2] dd 43 [2] d2 59 [2] cc 44 [2] ce 45 [2] d5 43 [2] c9 44 [2] d5 6b }

  condition:
    any of them
}