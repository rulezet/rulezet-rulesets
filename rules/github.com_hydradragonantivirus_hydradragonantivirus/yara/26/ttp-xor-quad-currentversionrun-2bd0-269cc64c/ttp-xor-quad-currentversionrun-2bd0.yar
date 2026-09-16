rule TTP_XOR_QUAD_CurrentVersionRun_2bd0 {
  strings:
    $key_2bd0 = { 78 bf [2] 5c b1 [2] 77 9d [2] 59 bf [2] 4d a4 [2] 42 be [2] 5c a3 [2] 5e a2 [2] 45 a4 [2] 59 a3 [2] 45 8c }

  condition:
    any of them
}