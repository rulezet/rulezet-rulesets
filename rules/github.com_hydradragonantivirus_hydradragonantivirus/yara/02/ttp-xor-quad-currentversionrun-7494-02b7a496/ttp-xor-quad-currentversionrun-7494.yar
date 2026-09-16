rule TTP_XOR_QUAD_CurrentVersionRun_7494 {
  strings:
    $key_7494 = { 27 fb [2] 03 f5 [2] 28 d9 [2] 06 fb [2] 12 e0 [2] 1d fa [2] 03 e7 [2] 01 e6 [2] 1a e0 [2] 06 e7 [2] 1a c8 }

  condition:
    any of them
}