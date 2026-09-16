rule TTP_XOR_QUAD_CurrentVersionRun_79e6 {
  strings:
    $key_79e6 = { 2a 89 [2] 0e 87 [2] 25 ab [2] 0b 89 [2] 1f 92 [2] 10 88 [2] 0e 95 [2] 0c 94 [2] 17 92 [2] 0b 95 [2] 17 ba }

  condition:
    any of them
}