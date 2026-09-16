rule TTP_XOR_QUAD_CurrentVersionRun_3f88 {
  strings:
    $key_3f88 = { 6c e7 [2] 48 e9 [2] 63 c5 [2] 4d e7 [2] 59 fc [2] 56 e6 [2] 48 fb [2] 4a fa [2] 51 fc [2] 4d fb [2] 51 d4 }

  condition:
    any of them
}