rule TTP_XOR_QUAD_CurrentVersionRun_d894 {
  strings:
    $key_d894 = { 8b fb [2] af f5 [2] 84 d9 [2] aa fb [2] be e0 [2] b1 fa [2] af e7 [2] ad e6 [2] b6 e0 [2] aa e7 [2] b6 c8 }

  condition:
    any of them
}