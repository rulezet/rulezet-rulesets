rule TTP_XOR_QUAD_CurrentVersionRun_04e6 {
  strings:
    $key_04e6 = { 57 89 [2] 73 87 [2] 58 ab [2] 76 89 [2] 62 92 [2] 6d 88 [2] 73 95 [2] 71 94 [2] 6a 92 [2] 76 95 [2] 6a ba }

  condition:
    any of them
}