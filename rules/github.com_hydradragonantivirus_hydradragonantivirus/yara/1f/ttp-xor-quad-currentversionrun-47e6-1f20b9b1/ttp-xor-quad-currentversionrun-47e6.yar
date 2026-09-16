rule TTP_XOR_QUAD_CurrentVersionRun_47e6 {
  strings:
    $key_47e6 = { 14 89 [2] 30 87 [2] 1b ab [2] 35 89 [2] 21 92 [2] 2e 88 [2] 30 95 [2] 32 94 [2] 29 92 [2] 35 95 [2] 29 ba }

  condition:
    any of them
}