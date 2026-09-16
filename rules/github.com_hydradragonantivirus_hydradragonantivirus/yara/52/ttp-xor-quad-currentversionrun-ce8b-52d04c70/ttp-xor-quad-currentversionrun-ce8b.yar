rule TTP_XOR_QUAD_CurrentVersionRun_ce8b {
  strings:
    $key_ce8b = { 9d e4 [2] b9 ea [2] 92 c6 [2] bc e4 [2] a8 ff [2] a7 e5 [2] b9 f8 [2] bb f9 [2] a0 ff [2] bc f8 [2] a0 d7 }

  condition:
    any of them
}