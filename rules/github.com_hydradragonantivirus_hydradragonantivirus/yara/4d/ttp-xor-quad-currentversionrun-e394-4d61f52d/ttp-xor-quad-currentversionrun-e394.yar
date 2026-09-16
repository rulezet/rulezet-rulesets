rule TTP_XOR_QUAD_CurrentVersionRun_e394 {
  strings:
    $key_e394 = { b0 fb [2] 94 f5 [2] bf d9 [2] 91 fb [2] 85 e0 [2] 8a fa [2] 94 e7 [2] 96 e6 [2] 8d e0 [2] 91 e7 [2] 8d c8 }

  condition:
    any of them
}