rule TTP_XOR_QUAD_CurrentVersionRun_0dd0 {
  strings:
    $key_0dd0 = { 5e bf [2] 7a b1 [2] 51 9d [2] 7f bf [2] 6b a4 [2] 64 be [2] 7a a3 [2] 78 a2 [2] 63 a4 [2] 7f a3 [2] 63 8c }

  condition:
    any of them
}