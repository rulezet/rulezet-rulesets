rule TTP_XOR_QUAD_CurrentVersionRun_24d0 {
  strings:
    $key_24d0 = { 77 bf [2] 53 b1 [2] 78 9d [2] 56 bf [2] 42 a4 [2] 4d be [2] 53 a3 [2] 51 a2 [2] 4a a4 [2] 56 a3 [2] 4a 8c }

  condition:
    any of them
}