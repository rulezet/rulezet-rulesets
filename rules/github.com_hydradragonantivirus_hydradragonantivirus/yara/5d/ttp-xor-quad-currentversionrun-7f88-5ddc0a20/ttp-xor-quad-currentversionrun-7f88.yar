rule TTP_XOR_QUAD_CurrentVersionRun_7f88 {
  strings:
    $key_7f88 = { 2c e7 [2] 08 e9 [2] 23 c5 [2] 0d e7 [2] 19 fc [2] 16 e6 [2] 08 fb [2] 0a fa [2] 11 fc [2] 0d fb [2] 11 d4 }

  condition:
    any of them
}