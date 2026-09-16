rule TTP_XOR_QUAD_CurrentVersionRun_bb55 {
  strings:
    $key_bb55 = { e8 3a [2] cc 34 [2] e7 18 [2] c9 3a [2] dd 21 [2] d2 3b [2] cc 26 [2] ce 27 [2] d5 21 [2] c9 26 [2] d5 09 }

  condition:
    any of them
}