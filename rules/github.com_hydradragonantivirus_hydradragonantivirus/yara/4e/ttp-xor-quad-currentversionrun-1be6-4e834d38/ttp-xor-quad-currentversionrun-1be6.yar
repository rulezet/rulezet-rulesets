rule TTP_XOR_QUAD_CurrentVersionRun_1be6 {
  strings:
    $key_1be6 = { 48 89 [2] 6c 87 [2] 47 ab [2] 69 89 [2] 7d 92 [2] 72 88 [2] 6c 95 [2] 6e 94 [2] 75 92 [2] 69 95 [2] 75 ba }

  condition:
    any of them
}