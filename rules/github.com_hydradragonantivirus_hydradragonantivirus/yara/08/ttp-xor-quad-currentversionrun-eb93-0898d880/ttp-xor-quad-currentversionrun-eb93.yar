rule TTP_XOR_QUAD_CurrentVersionRun_eb93 {
  strings:
    $key_eb93 = { b8 fc [2] 9c f2 [2] b7 de [2] 99 fc [2] 8d e7 [2] 82 fd [2] 9c e0 [2] 9e e1 [2] 85 e7 [2] 99 e0 [2] 85 cf }

  condition:
    any of them
}