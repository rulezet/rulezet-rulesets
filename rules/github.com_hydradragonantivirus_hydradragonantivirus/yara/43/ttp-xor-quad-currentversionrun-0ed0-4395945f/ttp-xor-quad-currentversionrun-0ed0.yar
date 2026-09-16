rule TTP_XOR_QUAD_CurrentVersionRun_0ed0 {
  strings:
    $key_0ed0 = { 5d bf [2] 79 b1 [2] 52 9d [2] 7c bf [2] 68 a4 [2] 67 be [2] 79 a3 [2] 7b a2 [2] 60 a4 [2] 7c a3 [2] 60 8c }

  condition:
    any of them
}