rule TTP_XOR_QUAD_CurrentVersionRun_d2d2 {
  strings:
    $key_d2d2 = { 81 bd [2] a5 b3 [2] 8e 9f [2] a0 bd [2] b4 a6 [2] bb bc [2] a5 a1 [2] a7 a0 [2] bc a6 [2] a0 a1 [2] bc 8e }

  condition:
    any of them
}