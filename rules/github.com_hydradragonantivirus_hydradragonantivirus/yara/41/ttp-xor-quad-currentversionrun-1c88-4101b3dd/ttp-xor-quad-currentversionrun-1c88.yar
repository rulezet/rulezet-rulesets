rule TTP_XOR_QUAD_CurrentVersionRun_1c88 {
  strings:
    $key_1c88 = { 4f e7 [2] 6b e9 [2] 40 c5 [2] 6e e7 [2] 7a fc [2] 75 e6 [2] 6b fb [2] 69 fa [2] 72 fc [2] 6e fb [2] 72 d4 }

  condition:
    any of them
}