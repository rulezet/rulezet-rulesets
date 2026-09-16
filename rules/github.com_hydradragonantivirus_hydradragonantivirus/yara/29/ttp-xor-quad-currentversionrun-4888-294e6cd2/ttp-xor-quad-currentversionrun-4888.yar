rule TTP_XOR_QUAD_CurrentVersionRun_4888 {
  strings:
    $key_4888 = { 1b e7 [2] 3f e9 [2] 14 c5 [2] 3a e7 [2] 2e fc [2] 21 e6 [2] 3f fb [2] 3d fa [2] 26 fc [2] 3a fb [2] 26 d4 }

  condition:
    any of them
}