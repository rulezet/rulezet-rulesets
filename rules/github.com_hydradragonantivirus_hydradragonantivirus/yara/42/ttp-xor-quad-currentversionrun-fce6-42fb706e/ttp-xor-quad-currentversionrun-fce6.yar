rule TTP_XOR_QUAD_CurrentVersionRun_fce6 {
  strings:
    $key_fce6 = { af 89 [2] 8b 87 [2] a0 ab [2] 8e 89 [2] 9a 92 [2] 95 88 [2] 8b 95 [2] 89 94 [2] 92 92 [2] 8e 95 [2] 92 ba }

  condition:
    any of them
}