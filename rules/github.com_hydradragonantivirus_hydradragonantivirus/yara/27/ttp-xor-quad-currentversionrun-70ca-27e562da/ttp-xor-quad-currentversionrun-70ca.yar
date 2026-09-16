rule TTP_XOR_QUAD_CurrentVersionRun_70ca {
  strings:
    $key_70ca = { 23 a5 [2] 07 ab [2] 2c 87 [2] 02 a5 [2] 16 be [2] 19 a4 [2] 07 b9 [2] 05 b8 [2] 1e be [2] 02 b9 [2] 1e 96 }

  condition:
    any of them
}