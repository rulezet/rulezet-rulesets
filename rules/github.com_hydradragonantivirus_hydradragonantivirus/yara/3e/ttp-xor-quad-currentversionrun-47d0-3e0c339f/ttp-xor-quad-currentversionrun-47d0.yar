rule TTP_XOR_QUAD_CurrentVersionRun_47d0 {
  strings:
    $key_47d0 = { 14 bf [2] 30 b1 [2] 1b 9d [2] 35 bf [2] 21 a4 [2] 2e be [2] 30 a3 [2] 32 a2 [2] 29 a4 [2] 35 a3 [2] 29 8c }

  condition:
    any of them
}