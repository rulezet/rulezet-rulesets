rule TTP_XOR_QUAD_CurrentVersionRun_ca93 {
  strings:
    $key_ca93 = { 99 fc [2] bd f2 [2] 96 de [2] b8 fc [2] ac e7 [2] a3 fd [2] bd e0 [2] bf e1 [2] a4 e7 [2] b8 e0 [2] a4 cf }

  condition:
    any of them
}