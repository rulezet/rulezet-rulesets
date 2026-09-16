rule TTP_XOR_QUAD_CurrentVersionRun_2fd6 {
  strings:
    $key_2fd6 = { 7c b9 [2] 58 b7 [2] 73 9b [2] 5d b9 [2] 49 a2 [2] 46 b8 [2] 58 a5 [2] 5a a4 [2] 41 a2 [2] 5d a5 [2] 41 8a }

  condition:
    any of them
}