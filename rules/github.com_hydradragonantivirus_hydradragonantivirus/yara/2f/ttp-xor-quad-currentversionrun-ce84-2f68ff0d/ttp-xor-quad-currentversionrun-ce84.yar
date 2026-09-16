rule TTP_XOR_QUAD_CurrentVersionRun_ce84 {
  strings:
    $key_ce84 = { 9d eb [2] b9 e5 [2] 92 c9 [2] bc eb [2] a8 f0 [2] a7 ea [2] b9 f7 [2] bb f6 [2] a0 f0 [2] bc f7 [2] a0 d8 }

  condition:
    any of them
}