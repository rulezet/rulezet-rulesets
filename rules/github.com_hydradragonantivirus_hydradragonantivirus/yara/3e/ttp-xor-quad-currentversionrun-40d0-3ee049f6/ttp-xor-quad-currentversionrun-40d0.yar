rule TTP_XOR_QUAD_CurrentVersionRun_40d0 {
  strings:
    $key_40d0 = { 13 bf [2] 37 b1 [2] 1c 9d [2] 32 bf [2] 26 a4 [2] 29 be [2] 37 a3 [2] 35 a2 [2] 2e a4 [2] 32 a3 [2] 2e 8c }

  condition:
    any of them
}