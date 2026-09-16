rule TTP_XOR_QUAD_CurrentVersionRun_c987 {
  strings:
    $key_c987 = { 9a e8 [2] be e6 [2] 95 ca [2] bb e8 [2] af f3 [2] a0 e9 [2] be f4 [2] bc f5 [2] a7 f3 [2] bb f4 [2] a7 db }

  condition:
    any of them
}