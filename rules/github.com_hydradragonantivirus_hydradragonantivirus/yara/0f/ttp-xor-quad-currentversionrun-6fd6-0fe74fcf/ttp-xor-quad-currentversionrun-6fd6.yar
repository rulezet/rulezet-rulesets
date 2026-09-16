rule TTP_XOR_QUAD_CurrentVersionRun_6fd6 {
  strings:
    $key_6fd6 = { 3c b9 [2] 18 b7 [2] 33 9b [2] 1d b9 [2] 09 a2 [2] 06 b8 [2] 18 a5 [2] 1a a4 [2] 01 a2 [2] 1d a5 [2] 01 8a }

  condition:
    any of them
}