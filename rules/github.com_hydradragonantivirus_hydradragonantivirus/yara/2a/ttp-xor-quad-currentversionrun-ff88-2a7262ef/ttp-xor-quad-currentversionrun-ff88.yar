rule TTP_XOR_QUAD_CurrentVersionRun_ff88 {
  strings:
    $key_ff88 = { ac e7 [2] 88 e9 [2] a3 c5 [2] 8d e7 [2] 99 fc [2] 96 e6 [2] 88 fb [2] 8a fa [2] 91 fc [2] 8d fb [2] 91 d4 }

  condition:
    any of them
}