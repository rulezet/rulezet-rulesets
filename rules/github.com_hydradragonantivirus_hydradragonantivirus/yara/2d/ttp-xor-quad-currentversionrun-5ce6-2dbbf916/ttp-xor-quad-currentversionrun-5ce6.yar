rule TTP_XOR_QUAD_CurrentVersionRun_5ce6 {
  strings:
    $key_5ce6 = { 0f 89 [2] 2b 87 [2] 00 ab [2] 2e 89 [2] 3a 92 [2] 35 88 [2] 2b 95 [2] 29 94 [2] 32 92 [2] 2e 95 [2] 32 ba }

  condition:
    any of them
}