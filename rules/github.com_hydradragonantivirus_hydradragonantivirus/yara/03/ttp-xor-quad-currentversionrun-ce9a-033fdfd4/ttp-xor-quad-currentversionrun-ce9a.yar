rule TTP_XOR_QUAD_CurrentVersionRun_ce9a {
  strings:
    $key_ce9a = { 9d f5 [2] b9 fb [2] 92 d7 [2] bc f5 [2] a8 ee [2] a7 f4 [2] b9 e9 [2] bb e8 [2] a0 ee [2] bc e9 [2] a0 c6 }

  condition:
    any of them
}