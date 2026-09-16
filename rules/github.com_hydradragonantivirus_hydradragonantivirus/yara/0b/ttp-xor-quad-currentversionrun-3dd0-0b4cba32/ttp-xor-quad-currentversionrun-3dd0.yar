rule TTP_XOR_QUAD_CurrentVersionRun_3dd0 {
  strings:
    $key_3dd0 = { 6e bf [2] 4a b1 [2] 61 9d [2] 4f bf [2] 5b a4 [2] 54 be [2] 4a a3 [2] 48 a2 [2] 53 a4 [2] 4f a3 [2] 53 8c }

  condition:
    any of them
}