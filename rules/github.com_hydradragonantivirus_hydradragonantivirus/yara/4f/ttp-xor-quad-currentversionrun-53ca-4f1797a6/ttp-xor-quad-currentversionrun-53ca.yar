rule TTP_XOR_QUAD_CurrentVersionRun_53ca {
  strings:
    $key_53ca = { 00 a5 [2] 24 ab [2] 0f 87 [2] 21 a5 [2] 35 be [2] 3a a4 [2] 24 b9 [2] 26 b8 [2] 3d be [2] 21 b9 [2] 3d 96 }

  condition:
    any of them
}