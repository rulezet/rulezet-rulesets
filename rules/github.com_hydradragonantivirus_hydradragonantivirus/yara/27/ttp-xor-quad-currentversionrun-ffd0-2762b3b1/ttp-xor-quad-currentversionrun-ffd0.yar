rule TTP_XOR_QUAD_CurrentVersionRun_ffd0 {
  strings:
    $key_ffd0 = { ac bf [2] 88 b1 [2] a3 9d [2] 8d bf [2] 99 a4 [2] 96 be [2] 88 a3 [2] 8a a2 [2] 91 a4 [2] 8d a3 [2] 91 8c }

  condition:
    any of them
}