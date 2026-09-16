rule TTP_XOR_QUAD_CurrentVersionRun_f4ca {
  strings:
    $key_f4ca = { a7 a5 [2] 83 ab [2] a8 87 [2] 86 a5 [2] 92 be [2] 9d a4 [2] 83 b9 [2] 81 b8 [2] 9a be [2] 86 b9 [2] 9a 96 }

  condition:
    any of them
}