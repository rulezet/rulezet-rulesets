rule TTP_XOR_QUAD_CurrentVersionRun_f7ca {
  strings:
    $key_f7ca = { a4 a5 [2] 80 ab [2] ab 87 [2] 85 a5 [2] 91 be [2] 9e a4 [2] 80 b9 [2] 82 b8 [2] 99 be [2] 85 b9 [2] 99 96 }

  condition:
    any of them
}