rule TTP_XOR_QUAD_CurrentVersionRun_6888 {
  strings:
    $key_6888 = { 3b e7 [2] 1f e9 [2] 34 c5 [2] 1a e7 [2] 0e fc [2] 01 e6 [2] 1f fb [2] 1d fa [2] 06 fc [2] 1a fb [2] 06 d4 }

  condition:
    any of them
}