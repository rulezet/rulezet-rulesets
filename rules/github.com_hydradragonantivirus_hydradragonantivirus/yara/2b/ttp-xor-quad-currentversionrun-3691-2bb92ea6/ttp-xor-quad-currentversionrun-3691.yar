rule TTP_XOR_QUAD_CurrentVersionRun_3691 {
  strings:
    $key_3691 = { 65 fe [2] 41 f0 [2] 6a dc [2] 44 fe [2] 50 e5 [2] 5f ff [2] 41 e2 [2] 43 e3 [2] 58 e5 [2] 44 e2 [2] 58 cd }

  condition:
    any of them
}