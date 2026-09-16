rule TTP_XOR_QUAD_CurrentVersionRun_06ca {
  strings:
    $key_06ca = { 55 a5 [2] 71 ab [2] 5a 87 [2] 74 a5 [2] 60 be [2] 6f a4 [2] 71 b9 [2] 73 b8 [2] 68 be [2] 74 b9 [2] 68 96 }

  condition:
    any of them
}