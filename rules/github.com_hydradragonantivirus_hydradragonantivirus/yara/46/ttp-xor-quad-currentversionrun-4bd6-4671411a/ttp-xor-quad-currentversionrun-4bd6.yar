rule TTP_XOR_QUAD_CurrentVersionRun_4bd6 {
  strings:
    $key_4bd6 = { 18 b9 [2] 3c b7 [2] 17 9b [2] 39 b9 [2] 2d a2 [2] 22 b8 [2] 3c a5 [2] 3e a4 [2] 25 a2 [2] 39 a5 [2] 25 8a }

  condition:
    any of them
}