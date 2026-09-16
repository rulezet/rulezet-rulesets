rule TTP_XOR_QUAD_CurrentVersionRun_bbff {
  strings:
    $key_bbff = { e8 90 [2] cc 9e [2] e7 b2 [2] c9 90 [2] dd 8b [2] d2 91 [2] cc 8c [2] ce 8d [2] d5 8b [2] c9 8c [2] d5 a3 }

  condition:
    any of them
}