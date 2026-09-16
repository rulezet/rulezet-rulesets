rule TTP_XOR_QUAD_CurrentVersionRun_1fca {
  strings:
    $key_1fca = { 4c a5 [2] 68 ab [2] 43 87 [2] 6d a5 [2] 79 be [2] 76 a4 [2] 68 b9 [2] 6a b8 [2] 71 be [2] 6d b9 [2] 71 96 }

  condition:
    any of them
}