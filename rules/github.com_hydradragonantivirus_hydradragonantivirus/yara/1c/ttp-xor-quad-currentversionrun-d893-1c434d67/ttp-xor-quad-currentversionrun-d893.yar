rule TTP_XOR_QUAD_CurrentVersionRun_d893 {
  strings:
    $key_d893 = { 8b fc [2] af f2 [2] 84 de [2] aa fc [2] be e7 [2] b1 fd [2] af e0 [2] ad e1 [2] b6 e7 [2] aa e0 [2] b6 cf }

  condition:
    any of them
}