rule TTP_XOR_QUAD_CurrentVersionRun_c0e6 {
  strings:
    $key_c0e6 = { 93 89 [2] b7 87 [2] 9c ab [2] b2 89 [2] a6 92 [2] a9 88 [2] b7 95 [2] b5 94 [2] ae 92 [2] b2 95 [2] ae ba }

  condition:
    any of them
}