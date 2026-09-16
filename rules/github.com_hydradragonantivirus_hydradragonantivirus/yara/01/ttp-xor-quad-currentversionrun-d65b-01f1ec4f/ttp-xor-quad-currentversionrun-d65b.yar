rule TTP_XOR_QUAD_CurrentVersionRun_d65b {
  strings:
    $key_d65b = { 85 34 [2] a1 3a [2] 8a 16 [2] a4 34 [2] b0 2f [2] bf 35 [2] a1 28 [2] a3 29 [2] b8 2f [2] a4 28 [2] b8 07 }

  condition:
    any of them
}