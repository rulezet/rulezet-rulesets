rule TTP_XOR_QUAD_CurrentVersionRun_7a88 {
  strings:
    $key_7a88 = { 29 e7 [2] 0d e9 [2] 26 c5 [2] 08 e7 [2] 1c fc [2] 13 e6 [2] 0d fb [2] 0f fa [2] 14 fc [2] 08 fb [2] 14 d4 }

  condition:
    any of them
}