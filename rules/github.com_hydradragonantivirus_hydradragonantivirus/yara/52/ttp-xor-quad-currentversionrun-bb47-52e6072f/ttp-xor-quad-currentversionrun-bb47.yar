rule TTP_XOR_QUAD_CurrentVersionRun_bb47 {
  strings:
    $key_bb47 = { e8 28 [2] cc 26 [2] e7 0a [2] c9 28 [2] dd 33 [2] d2 29 [2] cc 34 [2] ce 35 [2] d5 33 [2] c9 34 [2] d5 1b }

  condition:
    any of them
}