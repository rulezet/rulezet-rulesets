rule TTP_XOR_QUAD_CurrentVersionRun_3ed1 {
  strings:
    $key_3ed1 = { 6d be [2] 49 b0 [2] 62 9c [2] 4c be [2] 58 a5 [2] 57 bf [2] 49 a2 [2] 4b a3 [2] 50 a5 [2] 4c a2 [2] 50 8d }

  condition:
    any of them
}