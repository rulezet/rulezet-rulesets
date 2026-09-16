rule TTP_XOR_QUAD_CurrentVersionRun_c984 {
  strings:
    $key_c984 = { 9a eb [2] be e5 [2] 95 c9 [2] bb eb [2] af f0 [2] a0 ea [2] be f7 [2] bc f6 [2] a7 f0 [2] bb f7 [2] a7 d8 }

  condition:
    any of them
}