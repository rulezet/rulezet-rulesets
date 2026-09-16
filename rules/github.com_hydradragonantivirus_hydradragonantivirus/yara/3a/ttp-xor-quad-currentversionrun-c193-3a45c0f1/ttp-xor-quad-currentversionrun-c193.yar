rule TTP_XOR_QUAD_CurrentVersionRun_c193 {
  strings:
    $key_c193 = { 92 fc [2] b6 f2 [2] 9d de [2] b3 fc [2] a7 e7 [2] a8 fd [2] b6 e0 [2] b4 e1 [2] af e7 [2] b3 e0 [2] af cf }

  condition:
    any of them
}