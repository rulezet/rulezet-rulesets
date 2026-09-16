rule TTP_XOR_QUAD_CurrentVersionRun_bb4b {
  strings:
    $key_bb4b = { e8 24 [2] cc 2a [2] e7 06 [2] c9 24 [2] dd 3f [2] d2 25 [2] cc 38 [2] ce 39 [2] d5 3f [2] c9 38 [2] d5 17 }

  condition:
    any of them
}