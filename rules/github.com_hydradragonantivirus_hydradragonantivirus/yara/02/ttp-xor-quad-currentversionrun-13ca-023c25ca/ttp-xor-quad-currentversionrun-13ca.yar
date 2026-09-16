rule TTP_XOR_QUAD_CurrentVersionRun_13ca {
  strings:
    $key_13ca = { 40 a5 [2] 64 ab [2] 4f 87 [2] 61 a5 [2] 75 be [2] 7a a4 [2] 64 b9 [2] 66 b8 [2] 7d be [2] 61 b9 [2] 7d 96 }

  condition:
    any of them
}