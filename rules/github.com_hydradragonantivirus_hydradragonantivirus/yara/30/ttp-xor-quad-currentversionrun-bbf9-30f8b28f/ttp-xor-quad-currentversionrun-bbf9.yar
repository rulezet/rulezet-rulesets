rule TTP_XOR_QUAD_CurrentVersionRun_bbf9 {
  strings:
    $key_bbf9 = { e8 96 [2] cc 98 [2] e7 b4 [2] c9 96 [2] dd 8d [2] d2 97 [2] cc 8a [2] ce 8b [2] d5 8d [2] c9 8a [2] d5 a5 }

  condition:
    any of them
}