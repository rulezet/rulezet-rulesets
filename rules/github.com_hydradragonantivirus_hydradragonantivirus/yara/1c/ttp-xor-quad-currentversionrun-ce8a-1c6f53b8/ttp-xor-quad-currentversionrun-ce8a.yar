rule TTP_XOR_QUAD_CurrentVersionRun_ce8a {
  strings:
    $key_ce8a = { 9d e5 [2] b9 eb [2] 92 c7 [2] bc e5 [2] a8 fe [2] a7 e4 [2] b9 f9 [2] bb f8 [2] a0 fe [2] bc f9 [2] a0 d6 }

  condition:
    any of them
}