rule TTP_XOR_QUAD_CurrentVersionRun_5bb7 {
  strings:
    $key_5bb7 = { 08 d8 [2] 2c d6 [2] 07 fa [2] 29 d8 [2] 3d c3 [2] 32 d9 [2] 2c c4 [2] 2e c5 [2] 35 c3 [2] 29 c4 [2] 35 eb }

  condition:
    any of them
}