rule TTP_XOR_QUAD_CurrentVersionRun_0391 {
  strings:
    $key_0391 = { 50 fe [2] 74 f0 [2] 5f dc [2] 71 fe [2] 65 e5 [2] 6a ff [2] 74 e2 [2] 76 e3 [2] 6d e5 [2] 71 e2 [2] 6d cd }

  condition:
    any of them
}