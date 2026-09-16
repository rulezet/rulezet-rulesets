rule TTP_XOR_QUAD_CurrentVersionRun_0fd0 {
  strings:
    $key_0fd0 = { 5c bf [2] 78 b1 [2] 53 9d [2] 7d bf [2] 69 a4 [2] 66 be [2] 78 a3 [2] 7a a2 [2] 61 a4 [2] 7d a3 [2] 61 8c }

  condition:
    any of them
}