rule TTP_XOR_QUAD_CurrentVersionRun_2c88 {
  strings:
    $key_2c88 = { 7f e7 [2] 5b e9 [2] 70 c5 [2] 5e e7 [2] 4a fc [2] 45 e6 [2] 5b fb [2] 59 fa [2] 42 fc [2] 5e fb [2] 42 d4 }

  condition:
    any of them
}