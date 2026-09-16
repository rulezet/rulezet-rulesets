rule TTP_XOR_QUAD_CurrentVersionRun_bb5a {
  strings:
    $key_bb5a = { e8 35 [2] cc 3b [2] e7 17 [2] c9 35 [2] dd 2e [2] d2 34 [2] cc 29 [2] ce 28 [2] d5 2e [2] c9 29 [2] d5 06 }

  condition:
    any of them
}