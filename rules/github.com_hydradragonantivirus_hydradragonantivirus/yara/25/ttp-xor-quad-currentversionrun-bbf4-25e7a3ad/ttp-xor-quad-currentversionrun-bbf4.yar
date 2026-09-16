rule TTP_XOR_QUAD_CurrentVersionRun_bbf4 {
  strings:
    $key_bbf4 = { e8 9b [2] cc 95 [2] e7 b9 [2] c9 9b [2] dd 80 [2] d2 9a [2] cc 87 [2] ce 86 [2] d5 80 [2] c9 87 [2] d5 a8 }

  condition:
    any of them
}