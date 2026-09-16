rule TTP_XOR_QUAD_CurrentVersionRun_07ca {
  strings:
    $key_07ca = { 54 a5 [2] 70 ab [2] 5b 87 [2] 75 a5 [2] 61 be [2] 6e a4 [2] 70 b9 [2] 72 b8 [2] 69 be [2] 75 b9 [2] 69 96 }

  condition:
    any of them
}