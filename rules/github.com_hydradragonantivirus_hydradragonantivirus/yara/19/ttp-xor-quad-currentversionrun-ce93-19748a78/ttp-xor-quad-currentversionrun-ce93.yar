rule TTP_XOR_QUAD_CurrentVersionRun_ce93 {
  strings:
    $key_ce93 = { 9d fc [2] b9 f2 [2] 92 de [2] bc fc [2] a8 e7 [2] a7 fd [2] b9 e0 [2] bb e1 [2] a0 e7 [2] bc e0 [2] a0 cf }

  condition:
    any of them
}