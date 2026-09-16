rule TTP_XOR_QUAD_CurrentVersionRun_fbd1 {
  strings:
    $key_fbd1 = { a8 be [2] 8c b0 [2] a7 9c [2] 89 be [2] 9d a5 [2] 92 bf [2] 8c a2 [2] 8e a3 [2] 95 a5 [2] 89 a2 [2] 95 8d }

  condition:
    any of them
}