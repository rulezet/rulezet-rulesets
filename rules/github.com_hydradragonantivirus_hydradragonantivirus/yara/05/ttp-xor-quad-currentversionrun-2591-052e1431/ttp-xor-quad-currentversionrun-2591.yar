rule TTP_XOR_QUAD_CurrentVersionRun_2591 {
  strings:
    $key_2591 = { 76 fe [2] 52 f0 [2] 79 dc [2] 57 fe [2] 43 e5 [2] 4c ff [2] 52 e2 [2] 50 e3 [2] 4b e5 [2] 57 e2 [2] 4b cd }

  condition:
    any of them
}