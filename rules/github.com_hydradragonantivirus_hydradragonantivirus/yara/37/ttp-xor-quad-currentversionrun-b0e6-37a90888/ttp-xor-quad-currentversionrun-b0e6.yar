rule TTP_XOR_QUAD_CurrentVersionRun_b0e6 {
  strings:
    $key_b0e6 = { e3 89 [2] c7 87 [2] ec ab [2] c2 89 [2] d6 92 [2] d9 88 [2] c7 95 [2] c5 94 [2] de 92 [2] c2 95 [2] de ba }

  condition:
    any of them
}