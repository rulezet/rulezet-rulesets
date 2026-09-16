rule TTP_XOR_QUAD_CurrentVersionRun_5fd1 {
  strings:
    $key_5fd1 = { 0c be [2] 28 b0 [2] 03 9c [2] 2d be [2] 39 a5 [2] 36 bf [2] 28 a2 [2] 2a a3 [2] 31 a5 [2] 2d a2 [2] 31 8d }

  condition:
    any of them
}