rule TTP_XOR_QUAD_CurrentVersionRun_6489 {
  strings:
    $key_6489 = { 37 e6 [2] 13 e8 [2] 38 c4 [2] 16 e6 [2] 02 fd [2] 0d e7 [2] 13 fa [2] 11 fb [2] 0a fd [2] 16 fa [2] 0a d5 }

  condition:
    any of them
}