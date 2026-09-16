rule TTP_XOR_QUAD_CurrentVersionRun_7a93 {
  strings:
    $key_7a93 = { 29 fc [2] 0d f2 [2] 26 de [2] 08 fc [2] 1c e7 [2] 13 fd [2] 0d e0 [2] 0f e1 [2] 14 e7 [2] 08 e0 [2] 14 cf }

  condition:
    any of them
}