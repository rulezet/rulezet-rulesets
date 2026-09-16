rule TTP_XOR_QUAD_CurrentVersionRun_ea93 {
  strings:
    $key_ea93 = { b9 fc [2] 9d f2 [2] b6 de [2] 98 fc [2] 8c e7 [2] 83 fd [2] 9d e0 [2] 9f e1 [2] 84 e7 [2] 98 e0 [2] 84 cf }

  condition:
    any of them
}