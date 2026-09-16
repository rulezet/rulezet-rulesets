rule TTP_XOR_QUAD_CurrentVersionRun_d589 {
  strings:
    $key_d589 = { 86 e6 [2] a2 e8 [2] 89 c4 [2] a7 e6 [2] b3 fd [2] bc e7 [2] a2 fa [2] a0 fb [2] bb fd [2] a7 fa [2] bb d5 }

  condition:
    any of them
}