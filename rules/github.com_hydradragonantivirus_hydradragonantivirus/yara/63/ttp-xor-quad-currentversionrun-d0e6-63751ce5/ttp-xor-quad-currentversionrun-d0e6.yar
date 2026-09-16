rule TTP_XOR_QUAD_CurrentVersionRun_d0e6 {
  strings:
    $key_d0e6 = { 83 89 [2] a7 87 [2] 8c ab [2] a2 89 [2] b6 92 [2] b9 88 [2] a7 95 [2] a5 94 [2] be 92 [2] a2 95 [2] be ba }

  condition:
    any of them
}