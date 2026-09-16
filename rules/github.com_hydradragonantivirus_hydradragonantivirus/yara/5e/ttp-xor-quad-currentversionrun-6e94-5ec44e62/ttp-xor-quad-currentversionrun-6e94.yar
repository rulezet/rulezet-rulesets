rule TTP_XOR_QUAD_CurrentVersionRun_6e94 {
  strings:
    $key_6e94 = { 3d fb [2] 19 f5 [2] 32 d9 [2] 1c fb [2] 08 e0 [2] 07 fa [2] 19 e7 [2] 1b e6 [2] 00 e0 [2] 1c e7 [2] 00 c8 }

  condition:
    any of them
}