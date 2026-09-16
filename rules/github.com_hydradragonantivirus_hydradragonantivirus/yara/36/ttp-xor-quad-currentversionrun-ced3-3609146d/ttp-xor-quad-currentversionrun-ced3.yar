rule TTP_XOR_QUAD_CurrentVersionRun_ced3 {
  strings:
    $key_ced3 = { 9d bc [2] b9 b2 [2] 92 9e [2] bc bc [2] a8 a7 [2] a7 bd [2] b9 a0 [2] bb a1 [2] a0 a7 [2] bc a0 [2] a0 8f }

  condition:
    any of them
}