rule TTP_XOR_QUAD_CurrentVersionRun_d6e6 {
  strings:
    $key_d6e6 = { 85 89 [2] a1 87 [2] 8a ab [2] a4 89 [2] b0 92 [2] bf 88 [2] a1 95 [2] a3 94 [2] b8 92 [2] a4 95 [2] b8 ba }

  condition:
    any of them
}