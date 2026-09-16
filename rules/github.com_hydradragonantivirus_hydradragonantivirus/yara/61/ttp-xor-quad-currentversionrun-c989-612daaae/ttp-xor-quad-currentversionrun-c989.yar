rule TTP_XOR_QUAD_CurrentVersionRun_c989 {
  strings:
    $key_c989 = { 9a e6 [2] be e8 [2] 95 c4 [2] bb e6 [2] af fd [2] a0 e7 [2] be fa [2] bc fb [2] a7 fd [2] bb fa [2] a7 d5 }

  condition:
    any of them
}