rule TTP_XOR_QUAD_CurrentVersionRun_3591 {
  strings:
    $key_3591 = { 66 fe [2] 42 f0 [2] 69 dc [2] 47 fe [2] 53 e5 [2] 5c ff [2] 42 e2 [2] 40 e3 [2] 5b e5 [2] 47 e2 [2] 5b cd }

  condition:
    any of them
}