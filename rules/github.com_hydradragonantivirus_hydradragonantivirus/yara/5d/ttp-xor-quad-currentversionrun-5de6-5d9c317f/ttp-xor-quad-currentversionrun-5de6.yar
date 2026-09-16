rule TTP_XOR_QUAD_CurrentVersionRun_5de6 {
  strings:
    $key_5de6 = { 0e 89 [2] 2a 87 [2] 01 ab [2] 2f 89 [2] 3b 92 [2] 34 88 [2] 2a 95 [2] 28 94 [2] 33 92 [2] 2f 95 [2] 33 ba }

  condition:
    any of them
}