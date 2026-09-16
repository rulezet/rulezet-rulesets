rule TTP_XOR_QUAD_CurrentVersionRun_3888 {
  strings:
    $key_3888 = { 6b e7 [2] 4f e9 [2] 64 c5 [2] 4a e7 [2] 5e fc [2] 51 e6 [2] 4f fb [2] 4d fa [2] 56 fc [2] 4a fb [2] 56 d4 }

  condition:
    any of them
}