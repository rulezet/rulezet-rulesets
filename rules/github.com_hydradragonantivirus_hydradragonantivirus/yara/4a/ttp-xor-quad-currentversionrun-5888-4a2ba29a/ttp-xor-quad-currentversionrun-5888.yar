rule TTP_XOR_QUAD_CurrentVersionRun_5888 {
  strings:
    $key_5888 = { 0b e7 [2] 2f e9 [2] 04 c5 [2] 2a e7 [2] 3e fc [2] 31 e6 [2] 2f fb [2] 2d fa [2] 36 fc [2] 2a fb [2] 36 d4 }

  condition:
    any of them
}