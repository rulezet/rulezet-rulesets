rule TTP_XOR_QUAD_CurrentVersionRun_4fd6 {
  strings:
    $key_4fd6 = { 1c b9 [2] 38 b7 [2] 13 9b [2] 3d b9 [2] 29 a2 [2] 26 b8 [2] 38 a5 [2] 3a a4 [2] 21 a2 [2] 3d a5 [2] 21 8a }

  condition:
    any of them
}