rule TTP_XOR_QUAD_CurrentVersionRun_64d1 {
  strings:
    $key_64d1 = { 37 be [2] 13 b0 [2] 38 9c [2] 16 be [2] 02 a5 [2] 0d bf [2] 13 a2 [2] 11 a3 [2] 0a a5 [2] 16 a2 [2] 0a 8d }

  condition:
    any of them
}