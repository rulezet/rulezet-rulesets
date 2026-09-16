rule TTP_XOR_QUAD_CurrentVersionRun_b3e6 {
  strings:
    $key_b3e6 = { e0 89 [2] c4 87 [2] ef ab [2] c1 89 [2] d5 92 [2] da 88 [2] c4 95 [2] c6 94 [2] dd 92 [2] c1 95 [2] dd ba }

  condition:
    any of them
}