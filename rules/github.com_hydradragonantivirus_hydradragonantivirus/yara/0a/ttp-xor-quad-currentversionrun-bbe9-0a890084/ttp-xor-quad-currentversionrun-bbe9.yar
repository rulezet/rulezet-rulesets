rule TTP_XOR_QUAD_CurrentVersionRun_bbe9 {
  strings:
    $key_bbe9 = { e8 86 [2] cc 88 [2] e7 a4 [2] c9 86 [2] dd 9d [2] d2 87 [2] cc 9a [2] ce 9b [2] d5 9d [2] c9 9a [2] d5 b5 }

  condition:
    any of them
}