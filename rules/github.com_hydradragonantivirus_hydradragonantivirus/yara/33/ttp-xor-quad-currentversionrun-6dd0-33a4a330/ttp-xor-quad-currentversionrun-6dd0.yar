rule TTP_XOR_QUAD_CurrentVersionRun_6dd0 {
  strings:
    $key_6dd0 = { 3e bf [2] 1a b1 [2] 31 9d [2] 1f bf [2] 0b a4 [2] 04 be [2] 1a a3 [2] 18 a2 [2] 03 a4 [2] 1f a3 [2] 03 8c }

  condition:
    any of them
}