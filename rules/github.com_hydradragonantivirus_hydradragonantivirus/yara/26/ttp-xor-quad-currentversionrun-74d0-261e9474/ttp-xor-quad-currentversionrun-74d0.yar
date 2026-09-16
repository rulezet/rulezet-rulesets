rule TTP_XOR_QUAD_CurrentVersionRun_74d0 {
  strings:
    $key_74d0 = { 27 bf [2] 03 b1 [2] 28 9d [2] 06 bf [2] 12 a4 [2] 1d be [2] 03 a3 [2] 01 a2 [2] 1a a4 [2] 06 a3 [2] 1a 8c }

  condition:
    any of them
}