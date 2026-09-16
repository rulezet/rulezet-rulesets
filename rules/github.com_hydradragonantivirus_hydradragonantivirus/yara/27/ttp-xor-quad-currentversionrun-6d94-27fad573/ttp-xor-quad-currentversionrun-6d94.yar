rule TTP_XOR_QUAD_CurrentVersionRun_6d94 {
  strings:
    $key_6d94 = { 3e fb [2] 1a f5 [2] 31 d9 [2] 1f fb [2] 0b e0 [2] 04 fa [2] 1a e7 [2] 18 e6 [2] 03 e0 [2] 1f e7 [2] 03 c8 }

  condition:
    any of them
}