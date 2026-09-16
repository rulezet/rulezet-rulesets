rule TTP_XOR_QUAD_CurrentVersionRun_fc97 {
  strings:
    $key_fc97 = { af f8 [2] 8b f6 [2] a0 da [2] 8e f8 [2] 9a e3 [2] 95 f9 [2] 8b e4 [2] 89 e5 [2] 92 e3 [2] 8e e4 [2] 92 cb }

  condition:
    any of them
}