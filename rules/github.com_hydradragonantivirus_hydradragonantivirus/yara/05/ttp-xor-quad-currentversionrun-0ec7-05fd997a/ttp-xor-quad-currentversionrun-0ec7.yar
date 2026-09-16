rule TTP_XOR_QUAD_CurrentVersionRun_0ec7 {
  strings:
    $key_0ec7 = { 5d a8 [2] 79 a6 [2] 52 8a [2] 7c a8 [2] 68 b3 [2] 67 a9 [2] 79 b4 [2] 7b b5 [2] 60 b3 [2] 7c b4 [2] 60 9b }

  condition:
    any of them
}