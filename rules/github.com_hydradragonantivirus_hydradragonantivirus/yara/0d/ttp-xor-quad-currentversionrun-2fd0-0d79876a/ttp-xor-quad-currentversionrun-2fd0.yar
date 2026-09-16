rule TTP_XOR_QUAD_CurrentVersionRun_2fd0 {
  strings:
    $key_2fd0 = { 7c bf [2] 58 b1 [2] 73 9d [2] 5d bf [2] 49 a4 [2] 46 be [2] 58 a3 [2] 5a a2 [2] 41 a4 [2] 5d a3 [2] 41 8c }

  condition:
    any of them
}