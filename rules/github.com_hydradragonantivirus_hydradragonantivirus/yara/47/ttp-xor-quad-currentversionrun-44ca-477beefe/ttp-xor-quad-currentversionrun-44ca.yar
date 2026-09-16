rule TTP_XOR_QUAD_CurrentVersionRun_44ca {
  strings:
    $key_44ca = { 17 a5 [2] 33 ab [2] 18 87 [2] 36 a5 [2] 22 be [2] 2d a4 [2] 33 b9 [2] 31 b8 [2] 2a be [2] 36 b9 [2] 2a 96 }

  condition:
    any of them
}