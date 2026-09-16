rule TTP_XOR_QUAD_CurrentVersionRun_da94 {
  strings:
    $key_da94 = { 89 fb [2] ad f5 [2] 86 d9 [2] a8 fb [2] bc e0 [2] b3 fa [2] ad e7 [2] af e6 [2] b4 e0 [2] a8 e7 [2] b4 c8 }

  condition:
    any of them
}