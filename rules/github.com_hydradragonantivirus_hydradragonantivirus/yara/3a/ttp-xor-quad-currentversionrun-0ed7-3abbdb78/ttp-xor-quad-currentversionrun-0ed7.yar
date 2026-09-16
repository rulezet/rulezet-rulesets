rule TTP_XOR_QUAD_CurrentVersionRun_0ed7 {
  strings:
    $key_0ed7 = { 5d b8 [2] 79 b6 [2] 52 9a [2] 7c b8 [2] 68 a3 [2] 67 b9 [2] 79 a4 [2] 7b a5 [2] 60 a3 [2] 7c a4 [2] 60 8b }

  condition:
    any of them
}