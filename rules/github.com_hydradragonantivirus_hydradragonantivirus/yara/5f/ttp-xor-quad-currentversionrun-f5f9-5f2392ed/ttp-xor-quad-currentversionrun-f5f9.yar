rule TTP_XOR_QUAD_CurrentVersionRun_f5f9 {
  strings:
    $key_f5f9 = { a6 96 [2] 82 98 [2] a9 b4 [2] 87 96 [2] 93 8d [2] 9c 97 [2] 82 8a [2] 80 8b [2] 9b 8d [2] 87 8a [2] 9b a5 }

  condition:
    any of them
}