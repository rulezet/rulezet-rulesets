rule TTP_XOR_QUAD_CurrentVersionRun_3bd1 {
  strings:
    $key_3bd1 = { 68 be [2] 4c b0 [2] 67 9c [2] 49 be [2] 5d a5 [2] 52 bf [2] 4c a2 [2] 4e a3 [2] 55 a5 [2] 49 a2 [2] 55 8d }

  condition:
    any of them
}