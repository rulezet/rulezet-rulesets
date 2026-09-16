rule TTP_XOR_QUAD_CurrentVersionRun_f0c7 {
  strings:
    $key_f0c7 = { a3 a8 [2] 87 a6 [2] ac 8a [2] 82 a8 [2] 96 b3 [2] 99 a9 [2] 87 b4 [2] 85 b5 [2] 9e b3 [2] 82 b4 [2] 9e 9b }

  condition:
    any of them
}