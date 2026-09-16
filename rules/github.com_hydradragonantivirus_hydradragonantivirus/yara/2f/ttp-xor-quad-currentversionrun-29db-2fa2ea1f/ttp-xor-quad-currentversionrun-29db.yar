rule TTP_XOR_QUAD_CurrentVersionRun_29db {
  strings:
    $key_29db = { 7a b4 [2] 5e ba [2] 75 96 [2] 5b b4 [2] 4f af [2] 40 b5 [2] 5e a8 [2] 5c a9 [2] 47 af [2] 5b a8 [2] 47 87 }

  condition:
    any of them
}