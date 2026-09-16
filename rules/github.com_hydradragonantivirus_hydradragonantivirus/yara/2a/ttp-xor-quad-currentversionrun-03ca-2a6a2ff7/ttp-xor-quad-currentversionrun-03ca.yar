rule TTP_XOR_QUAD_CurrentVersionRun_03ca {
  strings:
    $key_03ca = { 50 a5 [2] 74 ab [2] 5f 87 [2] 71 a5 [2] 65 be [2] 6a a4 [2] 74 b9 [2] 76 b8 [2] 6d be [2] 71 b9 [2] 6d 96 }

  condition:
    any of them
}