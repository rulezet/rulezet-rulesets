rule TTP_XOR_QUAD_CurrentVersionRun_64ca {
  strings:
    $key_64ca = { 37 a5 [2] 13 ab [2] 38 87 [2] 16 a5 [2] 02 be [2] 0d a4 [2] 13 b9 [2] 11 b8 [2] 0a be [2] 16 b9 [2] 0a 96 }

  condition:
    any of them
}