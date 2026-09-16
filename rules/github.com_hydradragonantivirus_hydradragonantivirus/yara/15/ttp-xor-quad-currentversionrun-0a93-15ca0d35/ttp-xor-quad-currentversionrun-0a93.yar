rule TTP_XOR_QUAD_CurrentVersionRun_0a93 {
  strings:
    $key_0a93 = { 59 fc [2] 7d f2 [2] 56 de [2] 78 fc [2] 6c e7 [2] 63 fd [2] 7d e0 [2] 7f e1 [2] 64 e7 [2] 78 e0 [2] 64 cf }

  condition:
    any of them
}