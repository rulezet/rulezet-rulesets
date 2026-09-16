rule TTP_XOR_QUAD_CurrentVersionRun_2dd0 {
  strings:
    $key_2dd0 = { 7e bf [2] 5a b1 [2] 71 9d [2] 5f bf [2] 4b a4 [2] 44 be [2] 5a a3 [2] 58 a2 [2] 43 a4 [2] 5f a3 [2] 43 8c }

  condition:
    any of them
}