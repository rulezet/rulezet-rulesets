rule TTP_XOR_QUAD_CurrentVersionRun_bb1a {
  strings:
    $key_bb1a = { e8 75 [2] cc 7b [2] e7 57 [2] c9 75 [2] dd 6e [2] d2 74 [2] cc 69 [2] ce 68 [2] d5 6e [2] c9 69 [2] d5 46 }

  condition:
    any of them
}