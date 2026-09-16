rule TTP_XOR_QUAD_CurrentVersionRun_70d0 {
  strings:
    $key_70d0 = { 23 bf [2] 07 b1 [2] 2c 9d [2] 02 bf [2] 16 a4 [2] 19 be [2] 07 a3 [2] 05 a2 [2] 1e a4 [2] 02 a3 [2] 1e 8c }

  condition:
    any of them
}