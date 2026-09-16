rule TTP_XOR_QUAD_CurrentVersionRun_7ed1 {
  strings:
    $key_7ed1 = { 2d be [2] 09 b0 [2] 22 9c [2] 0c be [2] 18 a5 [2] 17 bf [2] 09 a2 [2] 0b a3 [2] 10 a5 [2] 0c a2 [2] 10 8d }

  condition:
    any of them
}