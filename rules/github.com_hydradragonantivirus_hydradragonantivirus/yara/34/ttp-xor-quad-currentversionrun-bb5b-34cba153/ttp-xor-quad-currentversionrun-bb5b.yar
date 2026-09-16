rule TTP_XOR_QUAD_CurrentVersionRun_bb5b {
  strings:
    $key_bb5b = { e8 34 [2] cc 3a [2] e7 16 [2] c9 34 [2] dd 2f [2] d2 35 [2] cc 28 [2] ce 29 [2] d5 2f [2] c9 28 [2] d5 07 }

  condition:
    any of them
}