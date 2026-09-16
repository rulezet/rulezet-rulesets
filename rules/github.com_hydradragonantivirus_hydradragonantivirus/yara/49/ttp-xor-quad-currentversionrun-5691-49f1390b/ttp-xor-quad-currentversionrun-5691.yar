rule TTP_XOR_QUAD_CurrentVersionRun_5691 {
  strings:
    $key_5691 = { 05 fe [2] 21 f0 [2] 0a dc [2] 24 fe [2] 30 e5 [2] 3f ff [2] 21 e2 [2] 23 e3 [2] 38 e5 [2] 24 e2 [2] 38 cd }

  condition:
    any of them
}