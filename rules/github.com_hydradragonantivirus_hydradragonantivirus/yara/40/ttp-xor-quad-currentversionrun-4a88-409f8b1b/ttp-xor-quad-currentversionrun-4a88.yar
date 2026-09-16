rule TTP_XOR_QUAD_CurrentVersionRun_4a88 {
  strings:
    $key_4a88 = { 19 e7 [2] 3d e9 [2] 16 c5 [2] 38 e7 [2] 2c fc [2] 23 e6 [2] 3d fb [2] 3f fa [2] 24 fc [2] 38 fb [2] 24 d4 }

  condition:
    any of them
}