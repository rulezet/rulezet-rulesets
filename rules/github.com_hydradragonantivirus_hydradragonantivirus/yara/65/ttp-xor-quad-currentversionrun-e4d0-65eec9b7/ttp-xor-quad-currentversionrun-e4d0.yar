rule TTP_XOR_QUAD_CurrentVersionRun_e4d0 {
  strings:
    $key_e4d0 = { b7 bf [2] 93 b1 [2] b8 9d [2] 96 bf [2] 82 a4 [2] 8d be [2] 93 a3 [2] 91 a2 [2] 8a a4 [2] 96 a3 [2] 8a 8c }

  condition:
    any of them
}