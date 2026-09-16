rule TTP_XOR_QUAD_CurrentVersionRun_65e6 {
  strings:
    $key_65e6 = { 36 89 [2] 12 87 [2] 39 ab [2] 17 89 [2] 03 92 [2] 0c 88 [2] 12 95 [2] 10 94 [2] 0b 92 [2] 17 95 [2] 0b ba }

  condition:
    any of them
}