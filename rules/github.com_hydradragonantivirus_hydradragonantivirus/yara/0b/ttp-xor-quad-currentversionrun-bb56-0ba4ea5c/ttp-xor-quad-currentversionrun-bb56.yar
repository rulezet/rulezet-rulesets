rule TTP_XOR_QUAD_CurrentVersionRun_bb56 {
  strings:
    $key_bb56 = { e8 39 [2] cc 37 [2] e7 1b [2] c9 39 [2] dd 22 [2] d2 38 [2] cc 25 [2] ce 24 [2] d5 22 [2] c9 25 [2] d5 0a }

  condition:
    any of them
}