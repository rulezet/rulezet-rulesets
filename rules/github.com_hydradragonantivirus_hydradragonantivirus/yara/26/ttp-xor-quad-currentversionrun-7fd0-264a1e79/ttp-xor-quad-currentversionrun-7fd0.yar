rule TTP_XOR_QUAD_CurrentVersionRun_7fd0 {
  strings:
    $key_7fd0 = { 2c bf [2] 08 b1 [2] 23 9d [2] 0d bf [2] 19 a4 [2] 16 be [2] 08 a3 [2] 0a a2 [2] 11 a4 [2] 0d a3 [2] 11 8c }

  condition:
    any of them
}