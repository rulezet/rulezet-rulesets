rule TTP_XOR_QUAD_CurrentVersionRun_40ca {
  strings:
    $key_40ca = { 13 a5 [2] 37 ab [2] 1c 87 [2] 32 a5 [2] 26 be [2] 29 a4 [2] 37 b9 [2] 35 b8 [2] 2e be [2] 32 b9 [2] 2e 96 }

  condition:
    any of them
}