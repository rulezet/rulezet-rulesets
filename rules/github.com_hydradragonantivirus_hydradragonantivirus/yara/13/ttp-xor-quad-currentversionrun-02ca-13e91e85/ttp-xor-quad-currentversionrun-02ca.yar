rule TTP_XOR_QUAD_CurrentVersionRun_02ca {
  strings:
    $key_02ca = { 51 a5 [2] 75 ab [2] 5e 87 [2] 70 a5 [2] 64 be [2] 6b a4 [2] 75 b9 [2] 77 b8 [2] 6c be [2] 70 b9 [2] 6c 96 }

  condition:
    any of them
}