rule TTP_XOR_QUAD_CurrentVersionRun_ce88 {
  strings:
    $key_ce88 = { 9d e7 [2] b9 e9 [2] 92 c5 [2] bc e7 [2] a8 fc [2] a7 e6 [2] b9 fb [2] bb fa [2] a0 fc [2] bc fb [2] a0 d4 }

  condition:
    any of them
}