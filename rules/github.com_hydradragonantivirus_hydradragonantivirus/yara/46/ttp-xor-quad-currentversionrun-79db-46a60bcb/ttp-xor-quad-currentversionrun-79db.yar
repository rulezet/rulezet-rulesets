rule TTP_XOR_QUAD_CurrentVersionRun_79db {
  strings:
    $key_79db = { 2a b4 [2] 0e ba [2] 25 96 [2] 0b b4 [2] 1f af [2] 10 b5 [2] 0e a8 [2] 0c a9 [2] 17 af [2] 0b a8 [2] 17 87 }

  condition:
    any of them
}