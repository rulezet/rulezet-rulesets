rule TTP_XOR_QUAD_CurrentVersionRun_c1e6 {
  strings:
    $key_c1e6 = { 92 89 [2] b6 87 [2] 9d ab [2] b3 89 [2] a7 92 [2] a8 88 [2] b6 95 [2] b4 94 [2] af 92 [2] b3 95 [2] af ba }

  condition:
    any of them
}