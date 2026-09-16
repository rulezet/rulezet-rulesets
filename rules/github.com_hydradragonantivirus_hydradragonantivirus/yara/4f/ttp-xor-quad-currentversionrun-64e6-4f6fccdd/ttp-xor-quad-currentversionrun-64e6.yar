rule TTP_XOR_QUAD_CurrentVersionRun_64e6 {
  strings:
    $key_64e6 = { 37 89 [2] 13 87 [2] 38 ab [2] 16 89 [2] 02 92 [2] 0d 88 [2] 13 95 [2] 11 94 [2] 0a 92 [2] 16 95 [2] 0a ba }

  condition:
    any of them
}