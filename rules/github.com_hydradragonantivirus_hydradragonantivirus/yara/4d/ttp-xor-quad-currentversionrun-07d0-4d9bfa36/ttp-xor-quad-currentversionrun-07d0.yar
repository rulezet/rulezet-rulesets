rule TTP_XOR_QUAD_CurrentVersionRun_07d0 {
  strings:
    $key_07d0 = { 54 bf [2] 70 b1 [2] 5b 9d [2] 75 bf [2] 61 a4 [2] 6e be [2] 70 a3 [2] 72 a2 [2] 69 a4 [2] 75 a3 [2] 69 8c }

  condition:
    any of them
}