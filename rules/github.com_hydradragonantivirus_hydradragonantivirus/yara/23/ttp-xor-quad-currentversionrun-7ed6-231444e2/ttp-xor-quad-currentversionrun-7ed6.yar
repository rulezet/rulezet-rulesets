rule TTP_XOR_QUAD_CurrentVersionRun_7ed6 {
  strings:
    $key_7ed6 = { 2d b9 [2] 09 b7 [2] 22 9b [2] 0c b9 [2] 18 a2 [2] 17 b8 [2] 09 a5 [2] 0b a4 [2] 10 a2 [2] 0c a5 [2] 10 8a }

  condition:
    any of them
}