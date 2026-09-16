rule TTP_XOR_QUAD_CurrentVersionRun_45ca {
  strings:
    $key_45ca = { 16 a5 [2] 32 ab [2] 19 87 [2] 37 a5 [2] 23 be [2] 2c a4 [2] 32 b9 [2] 30 b8 [2] 2b be [2] 37 b9 [2] 2b 96 }

  condition:
    any of them
}