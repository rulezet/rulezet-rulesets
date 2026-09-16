rule TTP_XOR_QUAD_CurrentVersionRun_07d1 {
  strings:
    $key_07d1 = { 54 be [2] 70 b0 [2] 5b 9c [2] 75 be [2] 61 a5 [2] 6e bf [2] 70 a2 [2] 72 a3 [2] 69 a5 [2] 75 a2 [2] 69 8d }

  condition:
    any of them
}