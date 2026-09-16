rule TTP_XOR_QUAD_CurrentVersionRun_f3ca {
  strings:
    $key_f3ca = { a0 a5 [2] 84 ab [2] af 87 [2] 81 a5 [2] 95 be [2] 9a a4 [2] 84 b9 [2] 86 b8 [2] 9d be [2] 81 b9 [2] 9d 96 }

  condition:
    any of them
}