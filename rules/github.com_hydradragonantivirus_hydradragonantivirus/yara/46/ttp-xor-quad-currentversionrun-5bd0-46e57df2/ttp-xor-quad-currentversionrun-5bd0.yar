rule TTP_XOR_QUAD_CurrentVersionRun_5bd0 {
  strings:
    $key_5bd0 = { 08 bf [2] 2c b1 [2] 07 9d [2] 29 bf [2] 3d a4 [2] 32 be [2] 2c a3 [2] 2e a2 [2] 35 a4 [2] 29 a3 [2] 35 8c }

  condition:
    any of them
}