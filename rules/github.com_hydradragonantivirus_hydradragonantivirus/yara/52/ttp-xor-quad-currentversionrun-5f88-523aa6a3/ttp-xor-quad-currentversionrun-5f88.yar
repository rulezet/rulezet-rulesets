rule TTP_XOR_QUAD_CurrentVersionRun_5f88 {
  strings:
    $key_5f88 = { 0c e7 [2] 28 e9 [2] 03 c5 [2] 2d e7 [2] 39 fc [2] 36 e6 [2] 28 fb [2] 2a fa [2] 31 fc [2] 2d fb [2] 31 d4 }

  condition:
    any of them
}