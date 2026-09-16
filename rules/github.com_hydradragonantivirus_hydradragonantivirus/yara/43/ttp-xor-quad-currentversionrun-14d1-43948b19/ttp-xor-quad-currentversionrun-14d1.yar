rule TTP_XOR_QUAD_CurrentVersionRun_14d1 {
  strings:
    $key_14d1 = { 47 be [2] 63 b0 [2] 48 9c [2] 66 be [2] 72 a5 [2] 7d bf [2] 63 a2 [2] 61 a3 [2] 7a a5 [2] 66 a2 [2] 7a 8d }

  condition:
    any of them
}