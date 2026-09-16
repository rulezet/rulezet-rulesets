rule TTP_XOR_QUAD_CurrentVersionRun_6595 {
  strings:
    $key_6595 = { 36 fa [2] 12 f4 [2] 39 d8 [2] 17 fa [2] 03 e1 [2] 0c fb [2] 12 e6 [2] 10 e7 [2] 0b e1 [2] 17 e6 [2] 0b c9 }

  condition:
    any of them
}