rule TTP_XOR_QUAD_CurrentVersionRun_3188 {
  strings:
    $key_3188 = { 62 e7 [2] 46 e9 [2] 6d c5 [2] 43 e7 [2] 57 fc [2] 58 e6 [2] 46 fb [2] 44 fa [2] 5f fc [2] 43 fb [2] 5f d4 }

  condition:
    any of them
}