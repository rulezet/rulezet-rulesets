rule TTP_XOR_QUAD_CurrentVersionRun_6494 {
  strings:
    $key_6494 = { 37 fb [2] 13 f5 [2] 38 d9 [2] 16 fb [2] 02 e0 [2] 0d fa [2] 13 e7 [2] 11 e6 [2] 0a e0 [2] 16 e7 [2] 0a c8 }

  condition:
    any of them
}