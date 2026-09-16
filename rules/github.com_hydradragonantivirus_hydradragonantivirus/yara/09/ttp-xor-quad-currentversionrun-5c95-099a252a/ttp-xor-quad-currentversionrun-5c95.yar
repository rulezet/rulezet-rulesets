rule TTP_XOR_QUAD_CurrentVersionRun_5c95 {
  strings:
    $key_5c95 = { 0f fa [2] 2b f4 [2] 00 d8 [2] 2e fa [2] 3a e1 [2] 35 fb [2] 2b e6 [2] 29 e7 [2] 32 e1 [2] 2e e6 [2] 32 c9 }

  condition:
    any of them
}