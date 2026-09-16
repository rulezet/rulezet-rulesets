rule TTP_XOR_QUAD_CurrentVersionRun_c995 {
  strings:
    $key_c995 = { 9a fa [2] be f4 [2] 95 d8 [2] bb fa [2] af e1 [2] a0 fb [2] be e6 [2] bc e7 [2] a7 e1 [2] bb e6 [2] a7 c9 }

  condition:
    any of them
}