rule TTP_XOR_QUAD_CurrentVersionRun_f591 {
  strings:
    $key_f591 = { a6 fe [2] 82 f0 [2] a9 dc [2] 87 fe [2] 93 e5 [2] 9c ff [2] 82 e2 [2] 80 e3 [2] 9b e5 [2] 87 e2 [2] 9b cd }

  condition:
    any of them
}