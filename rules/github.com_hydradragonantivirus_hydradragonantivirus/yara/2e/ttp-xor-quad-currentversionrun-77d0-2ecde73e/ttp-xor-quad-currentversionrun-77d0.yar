rule TTP_XOR_QUAD_CurrentVersionRun_77d0 {
  strings:
    $key_77d0 = { 24 bf [2] 00 b1 [2] 2b 9d [2] 05 bf [2] 11 a4 [2] 1e be [2] 00 a3 [2] 02 a2 [2] 19 a4 [2] 05 a3 [2] 19 8c }

  condition:
    any of them
}