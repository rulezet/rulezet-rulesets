rule TTP_XOR_QUAD_CurrentVersionRun_c3e6 {
  strings:
    $key_c3e6 = { 90 89 [2] b4 87 [2] 9f ab [2] b1 89 [2] a5 92 [2] aa 88 [2] b4 95 [2] b6 94 [2] ad 92 [2] b1 95 [2] ad ba }

  condition:
    any of them
}