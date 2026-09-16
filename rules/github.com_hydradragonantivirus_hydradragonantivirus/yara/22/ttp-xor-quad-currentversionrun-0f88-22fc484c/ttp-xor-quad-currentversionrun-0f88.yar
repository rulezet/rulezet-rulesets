rule TTP_XOR_QUAD_CurrentVersionRun_0f88 {
  strings:
    $key_0f88 = { 5c e7 [2] 78 e9 [2] 53 c5 [2] 7d e7 [2] 69 fc [2] 66 e6 [2] 78 fb [2] 7a fa [2] 61 fc [2] 7d fb [2] 61 d4 }

  condition:
    any of them
}