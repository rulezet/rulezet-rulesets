rule TTP_XOR_QUAD_CurrentVersionRun_f6da {
  strings:
    $key_f6da = { a5 b5 [2] 81 bb [2] aa 97 [2] 84 b5 [2] 90 ae [2] 9f b4 [2] 81 a9 [2] 83 a8 [2] 98 ae [2] 84 a9 [2] 98 86 }

  condition:
    any of them
}