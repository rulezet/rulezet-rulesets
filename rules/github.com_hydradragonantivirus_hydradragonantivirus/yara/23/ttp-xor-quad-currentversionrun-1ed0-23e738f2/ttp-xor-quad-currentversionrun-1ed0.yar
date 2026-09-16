rule TTP_XOR_QUAD_CurrentVersionRun_1ed0 {
  strings:
    $key_1ed0 = { 4d bf [2] 69 b1 [2] 42 9d [2] 6c bf [2] 78 a4 [2] 77 be [2] 69 a3 [2] 6b a2 [2] 70 a4 [2] 6c a3 [2] 70 8c }

  condition:
    any of them
}