rule TTP_XOR_QUAD_CurrentVersionRun_77e6 {
  strings:
    $key_77e6 = { 24 89 [2] 00 87 [2] 2b ab [2] 05 89 [2] 11 92 [2] 1e 88 [2] 00 95 [2] 02 94 [2] 19 92 [2] 05 95 [2] 19 ba }

  condition:
    any of them
}