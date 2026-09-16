rule TTP_XOR_QUAD_CurrentVersionRun_2fca {
  strings:
    $key_2fca = { 7c a5 [2] 58 ab [2] 73 87 [2] 5d a5 [2] 49 be [2] 46 a4 [2] 58 b9 [2] 5a b8 [2] 41 be [2] 5d b9 [2] 41 96 }

  condition:
    any of them
}