rule TTP_XOR_QUAD_CurrentVersionRun_2391 {
  strings:
    $key_2391 = { 70 fe [2] 54 f0 [2] 7f dc [2] 51 fe [2] 45 e5 [2] 4a ff [2] 54 e2 [2] 56 e3 [2] 4d e5 [2] 51 e2 [2] 4d cd }

  condition:
    any of them
}