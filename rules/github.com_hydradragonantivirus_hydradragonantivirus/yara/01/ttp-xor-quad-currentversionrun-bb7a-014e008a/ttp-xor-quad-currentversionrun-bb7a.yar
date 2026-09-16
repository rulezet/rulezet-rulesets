rule TTP_XOR_QUAD_CurrentVersionRun_bb7a {
  strings:
    $key_bb7a = { e8 15 [2] cc 1b [2] e7 37 [2] c9 15 [2] dd 0e [2] d2 14 [2] cc 09 [2] ce 08 [2] d5 0e [2] c9 09 [2] d5 26 }

  condition:
    any of them
}