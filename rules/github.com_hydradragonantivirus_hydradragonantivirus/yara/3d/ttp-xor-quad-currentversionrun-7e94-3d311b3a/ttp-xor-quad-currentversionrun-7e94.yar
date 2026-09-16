rule TTP_XOR_QUAD_CurrentVersionRun_7e94 {
  strings:
    $key_7e94 = { 2d fb [2] 09 f5 [2] 22 d9 [2] 0c fb [2] 18 e0 [2] 17 fa [2] 09 e7 [2] 0b e6 [2] 10 e0 [2] 0c e7 [2] 10 c8 }

  condition:
    any of them
}