rule TTP_XOR_QUAD_CurrentVersionRun_d7e6 {
  strings:
    $key_d7e6 = { 84 89 [2] a0 87 [2] 8b ab [2] a5 89 [2] b1 92 [2] be 88 [2] a0 95 [2] a2 94 [2] b9 92 [2] a5 95 [2] b9 ba }

  condition:
    any of them
}