rule TTP_XOR_QUAD_CurrentVersionRun_66ca {
  strings:
    $key_66ca = { 35 a5 [2] 11 ab [2] 3a 87 [2] 14 a5 [2] 00 be [2] 0f a4 [2] 11 b9 [2] 13 b8 [2] 08 be [2] 14 b9 [2] 08 96 }

  condition:
    any of them
}