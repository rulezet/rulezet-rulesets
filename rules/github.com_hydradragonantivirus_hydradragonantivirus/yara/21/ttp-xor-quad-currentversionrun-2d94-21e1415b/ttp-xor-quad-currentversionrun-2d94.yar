rule TTP_XOR_QUAD_CurrentVersionRun_2d94 {
  strings:
    $key_2d94 = { 7e fb [2] 5a f5 [2] 71 d9 [2] 5f fb [2] 4b e0 [2] 44 fa [2] 5a e7 [2] 58 e6 [2] 43 e0 [2] 5f e7 [2] 43 c8 }

  condition:
    any of them
}