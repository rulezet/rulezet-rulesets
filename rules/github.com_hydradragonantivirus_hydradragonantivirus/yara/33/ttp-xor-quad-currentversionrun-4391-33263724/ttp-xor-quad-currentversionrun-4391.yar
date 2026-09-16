rule TTP_XOR_QUAD_CurrentVersionRun_4391 {
  strings:
    $key_4391 = { 10 fe [2] 34 f0 [2] 1f dc [2] 31 fe [2] 25 e5 [2] 2a ff [2] 34 e2 [2] 36 e3 [2] 2d e5 [2] 31 e2 [2] 2d cd }

  condition:
    any of them
}