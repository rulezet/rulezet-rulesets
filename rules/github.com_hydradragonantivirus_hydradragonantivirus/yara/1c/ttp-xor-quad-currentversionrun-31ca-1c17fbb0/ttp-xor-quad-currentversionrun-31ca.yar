rule TTP_XOR_QUAD_CurrentVersionRun_31ca {
  strings:
    $key_31ca = { 62 a5 [2] 46 ab [2] 6d 87 [2] 43 a5 [2] 57 be [2] 58 a4 [2] 46 b9 [2] 44 b8 [2] 5f be [2] 43 b9 [2] 5f 96 }

  condition:
    any of them
}