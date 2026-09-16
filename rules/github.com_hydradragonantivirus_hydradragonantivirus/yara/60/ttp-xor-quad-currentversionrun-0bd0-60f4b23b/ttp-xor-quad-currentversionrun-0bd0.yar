rule TTP_XOR_QUAD_CurrentVersionRun_0bd0 {
  strings:
    $key_0bd0 = { 58 bf [2] 7c b1 [2] 57 9d [2] 79 bf [2] 6d a4 [2] 62 be [2] 7c a3 [2] 7e a2 [2] 65 a4 [2] 79 a3 [2] 65 8c }

  condition:
    any of them
}