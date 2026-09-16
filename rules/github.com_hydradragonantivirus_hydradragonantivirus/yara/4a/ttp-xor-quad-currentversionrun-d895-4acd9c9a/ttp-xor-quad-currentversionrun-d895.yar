rule TTP_XOR_QUAD_CurrentVersionRun_d895 {
  strings:
    $key_d895 = { 8b fa [2] af f4 [2] 84 d8 [2] aa fa [2] be e1 [2] b1 fb [2] af e6 [2] ad e7 [2] b6 e1 [2] aa e6 [2] b6 c9 }

  condition:
    any of them
}