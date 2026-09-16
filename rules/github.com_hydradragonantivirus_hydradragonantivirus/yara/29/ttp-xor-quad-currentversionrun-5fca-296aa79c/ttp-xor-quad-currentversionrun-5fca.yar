rule TTP_XOR_QUAD_CurrentVersionRun_5fca {
  strings:
    $key_5fca = { 0c a5 [2] 28 ab [2] 03 87 [2] 2d a5 [2] 39 be [2] 36 a4 [2] 28 b9 [2] 2a b8 [2] 31 be [2] 2d b9 [2] 31 96 }

  condition:
    any of them
}