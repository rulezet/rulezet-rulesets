rule TTP_XOR_QUAD_CurrentVersionRun_bb44 {
  strings:
    $key_bb44 = { e8 2b [2] cc 25 [2] e7 09 [2] c9 2b [2] dd 30 [2] d2 2a [2] cc 37 [2] ce 36 [2] d5 30 [2] c9 37 [2] d5 18 }

  condition:
    any of them
}