rule TTP_XOR_QUAD_CurrentVersionRun_4c88 {
  strings:
    $key_4c88 = { 1f e7 [2] 3b e9 [2] 10 c5 [2] 3e e7 [2] 2a fc [2] 25 e6 [2] 3b fb [2] 39 fa [2] 22 fc [2] 3e fb [2] 22 d4 }

  condition:
    any of them
}