rule TTP_XOR_QUAD_CurrentVersionRun_6391 {
  strings:
    $key_6391 = { 30 fe [2] 14 f0 [2] 3f dc [2] 11 fe [2] 05 e5 [2] 0a ff [2] 14 e2 [2] 16 e3 [2] 0d e5 [2] 11 e2 [2] 0d cd }

  condition:
    any of them
}