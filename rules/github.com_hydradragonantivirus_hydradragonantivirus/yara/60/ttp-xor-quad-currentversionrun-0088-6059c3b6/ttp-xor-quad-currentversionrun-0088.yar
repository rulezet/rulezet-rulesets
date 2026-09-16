rule TTP_XOR_QUAD_CurrentVersionRun_0088 {
  strings:
    $key_0088 = { 53 e7 [2] 77 e9 [2] 5c c5 [2] 72 e7 [2] 66 fc [2] 69 e6 [2] 77 fb [2] 75 fa [2] 6e fc [2] 72 fb [2] 6e d4 }

  condition:
    any of them
}