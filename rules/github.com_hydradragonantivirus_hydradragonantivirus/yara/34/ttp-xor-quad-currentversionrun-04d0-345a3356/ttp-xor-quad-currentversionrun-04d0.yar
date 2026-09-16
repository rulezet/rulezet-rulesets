rule TTP_XOR_QUAD_CurrentVersionRun_04d0 {
  strings:
    $key_04d0 = { 57 bf [2] 73 b1 [2] 58 9d [2] 76 bf [2] 62 a4 [2] 6d be [2] 73 a3 [2] 71 a2 [2] 6a a4 [2] 76 a3 [2] 6a 8c }

  condition:
    any of them
}