rule TTP_XOR_QUAD_CurrentVersionRun_0c88 {
  strings:
    $key_0c88 = { 5f e7 [2] 7b e9 [2] 50 c5 [2] 7e e7 [2] 6a fc [2] 65 e6 [2] 7b fb [2] 79 fa [2] 62 fc [2] 7e fb [2] 62 d4 }

  condition:
    any of them
}