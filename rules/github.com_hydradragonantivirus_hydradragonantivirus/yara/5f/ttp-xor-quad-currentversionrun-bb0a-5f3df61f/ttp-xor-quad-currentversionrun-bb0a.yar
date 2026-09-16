rule TTP_XOR_QUAD_CurrentVersionRun_bb0a {
  strings:
    $key_bb0a = { e8 65 [2] cc 6b [2] e7 47 [2] c9 65 [2] dd 7e [2] d2 64 [2] cc 79 [2] ce 78 [2] d5 7e [2] c9 79 [2] d5 56 }

  condition:
    any of them
}