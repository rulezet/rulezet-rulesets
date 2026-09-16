rule TTP_XOR_QUAD_CurrentVersionRun_3bd0 {
  strings:
    $key_3bd0 = { 68 bf [2] 4c b1 [2] 67 9d [2] 49 bf [2] 5d a4 [2] 52 be [2] 4c a3 [2] 4e a2 [2] 55 a4 [2] 49 a3 [2] 55 8c }

  condition:
    any of them
}