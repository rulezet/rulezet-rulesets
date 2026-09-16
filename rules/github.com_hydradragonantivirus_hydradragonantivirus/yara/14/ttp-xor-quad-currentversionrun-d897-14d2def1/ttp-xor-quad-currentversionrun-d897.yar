rule TTP_XOR_QUAD_CurrentVersionRun_d897 {
  strings:
    $key_d897 = { 8b f8 [2] af f6 [2] 84 da [2] aa f8 [2] be e3 [2] b1 f9 [2] af e4 [2] ad e5 [2] b6 e3 [2] aa e4 [2] b6 cb }

  condition:
    any of them
}