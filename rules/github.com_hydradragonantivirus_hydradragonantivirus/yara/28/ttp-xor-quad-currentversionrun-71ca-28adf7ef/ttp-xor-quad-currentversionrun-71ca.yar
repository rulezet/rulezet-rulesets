rule TTP_XOR_QUAD_CurrentVersionRun_71ca {
  strings:
    $key_71ca = { 22 a5 [2] 06 ab [2] 2d 87 [2] 03 a5 [2] 17 be [2] 18 a4 [2] 06 b9 [2] 04 b8 [2] 1f be [2] 03 b9 [2] 1f 96 }

  condition:
    any of them
}