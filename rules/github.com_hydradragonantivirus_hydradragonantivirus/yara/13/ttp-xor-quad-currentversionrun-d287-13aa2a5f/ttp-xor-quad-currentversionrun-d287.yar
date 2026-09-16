rule TTP_XOR_QUAD_CurrentVersionRun_d287 {
  strings:
    $key_d287 = { 81 e8 [2] a5 e6 [2] 8e ca [2] a0 e8 [2] b4 f3 [2] bb e9 [2] a5 f4 [2] a7 f5 [2] bc f3 [2] a0 f4 [2] bc db }

  condition:
    any of them
}