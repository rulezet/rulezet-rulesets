rule TTP_XOR_QUAD_CurrentVersionRun_4dd0 {
  strings:
    $key_4dd0 = { 1e bf [2] 3a b1 [2] 11 9d [2] 3f bf [2] 2b a4 [2] 24 be [2] 3a a3 [2] 38 a2 [2] 23 a4 [2] 3f a3 [2] 23 8c }

  condition:
    any of them
}