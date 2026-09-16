rule TTP_XOR_QUAD_CurrentVersionRun_1489 {
  strings:
    $key_1489 = { 47 e6 [2] 63 e8 [2] 48 c4 [2] 66 e6 [2] 72 fd [2] 7d e7 [2] 63 fa [2] 61 fb [2] 7a fd [2] 66 fa [2] 7a d5 }

  condition:
    any of them
}