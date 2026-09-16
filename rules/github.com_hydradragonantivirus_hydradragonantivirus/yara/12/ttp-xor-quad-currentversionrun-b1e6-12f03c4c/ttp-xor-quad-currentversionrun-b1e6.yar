rule TTP_XOR_QUAD_CurrentVersionRun_b1e6 {
  strings:
    $key_b1e6 = { e2 89 [2] c6 87 [2] ed ab [2] c3 89 [2] d7 92 [2] d8 88 [2] c6 95 [2] c4 94 [2] df 92 [2] c3 95 [2] df ba }

  condition:
    any of them
}