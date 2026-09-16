rule TTP_XOR_QUAD_CurrentVersionRun_5c94 {
  strings:
    $key_5c94 = { 0f fb [2] 2b f5 [2] 00 d9 [2] 2e fb [2] 3a e0 [2] 35 fa [2] 2b e7 [2] 29 e6 [2] 32 e0 [2] 2e e7 [2] 32 c8 }

  condition:
    any of them
}