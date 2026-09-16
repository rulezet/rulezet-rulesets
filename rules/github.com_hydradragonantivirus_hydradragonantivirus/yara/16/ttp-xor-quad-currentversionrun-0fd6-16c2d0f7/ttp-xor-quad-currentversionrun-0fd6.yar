rule TTP_XOR_QUAD_CurrentVersionRun_0fd6 {
  strings:
    $key_0fd6 = { 5c b9 [2] 78 b7 [2] 53 9b [2] 7d b9 [2] 69 a2 [2] 66 b8 [2] 78 a5 [2] 7a a4 [2] 61 a2 [2] 7d a5 [2] 61 8a }

  condition:
    any of them
}