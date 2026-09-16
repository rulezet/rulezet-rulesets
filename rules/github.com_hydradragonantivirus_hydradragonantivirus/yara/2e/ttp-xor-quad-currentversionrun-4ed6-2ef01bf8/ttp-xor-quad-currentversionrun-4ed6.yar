rule TTP_XOR_QUAD_CurrentVersionRun_4ed6 {
  strings:
    $key_4ed6 = { 1d b9 [2] 39 b7 [2] 12 9b [2] 3c b9 [2] 28 a2 [2] 27 b8 [2] 39 a5 [2] 3b a4 [2] 20 a2 [2] 3c a5 [2] 20 8a }

  condition:
    any of them
}