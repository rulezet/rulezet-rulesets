rule TTP_XOR_QUAD_CurrentVersionRun_0be6 {
  strings:
    $key_0be6 = { 58 89 [2] 7c 87 [2] 57 ab [2] 79 89 [2] 6d 92 [2] 62 88 [2] 7c 95 [2] 7e 94 [2] 65 92 [2] 79 95 [2] 65 ba }

  condition:
    any of them
}