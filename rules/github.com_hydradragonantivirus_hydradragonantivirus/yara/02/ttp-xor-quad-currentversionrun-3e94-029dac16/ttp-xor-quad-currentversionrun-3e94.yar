rule TTP_XOR_QUAD_CurrentVersionRun_3e94 {
  strings:
    $key_3e94 = { 6d fb [2] 49 f5 [2] 62 d9 [2] 4c fb [2] 58 e0 [2] 57 fa [2] 49 e7 [2] 4b e6 [2] 50 e0 [2] 4c e7 [2] 50 c8 }

  condition:
    any of them
}