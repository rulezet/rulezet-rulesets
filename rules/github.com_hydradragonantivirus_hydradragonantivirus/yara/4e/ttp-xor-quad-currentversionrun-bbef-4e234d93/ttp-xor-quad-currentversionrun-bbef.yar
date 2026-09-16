rule TTP_XOR_QUAD_CurrentVersionRun_bbef {
  strings:
    $key_bbef = { e8 80 [2] cc 8e [2] e7 a2 [2] c9 80 [2] dd 9b [2] d2 81 [2] cc 9c [2] ce 9d [2] d5 9b [2] c9 9c [2] d5 b3 }

  condition:
    any of them
}