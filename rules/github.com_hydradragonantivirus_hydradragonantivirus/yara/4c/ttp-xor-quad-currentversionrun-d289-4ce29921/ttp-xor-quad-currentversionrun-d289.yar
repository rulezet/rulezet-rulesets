rule TTP_XOR_QUAD_CurrentVersionRun_d289 {
  strings:
    $key_d289 = { 81 e6 [2] a5 e8 [2] 8e c4 [2] a0 e6 [2] b4 fd [2] bb e7 [2] a5 fa [2] a7 fb [2] bc fd [2] a0 fa [2] bc d5 }

  condition:
    any of them
}