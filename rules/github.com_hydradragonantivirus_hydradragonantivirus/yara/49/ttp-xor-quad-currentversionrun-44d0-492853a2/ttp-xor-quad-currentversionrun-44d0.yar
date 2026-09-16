rule TTP_XOR_QUAD_CurrentVersionRun_44d0 {
  strings:
    $key_44d0 = { 17 bf [2] 33 b1 [2] 18 9d [2] 36 bf [2] 22 a4 [2] 2d be [2] 33 a3 [2] 31 a2 [2] 2a a4 [2] 36 a3 [2] 2a 8c }

  condition:
    any of them
}