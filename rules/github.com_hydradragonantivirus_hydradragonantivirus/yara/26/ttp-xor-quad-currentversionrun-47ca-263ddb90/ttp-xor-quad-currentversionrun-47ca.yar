rule TTP_XOR_QUAD_CurrentVersionRun_47ca {
  strings:
    $key_47ca = { 14 a5 [2] 30 ab [2] 1b 87 [2] 35 a5 [2] 21 be [2] 2e a4 [2] 30 b9 [2] 32 b8 [2] 29 be [2] 35 b9 [2] 29 96 }

  condition:
    any of them
}