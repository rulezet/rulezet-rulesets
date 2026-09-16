rule TTP_XOR_QUAD_CurrentVersionRun_7d94 {
  strings:
    $key_7d94 = { 2e fb [2] 0a f5 [2] 21 d9 [2] 0f fb [2] 1b e0 [2] 14 fa [2] 0a e7 [2] 08 e6 [2] 13 e0 [2] 0f e7 [2] 13 c8 }

  condition:
    any of them
}