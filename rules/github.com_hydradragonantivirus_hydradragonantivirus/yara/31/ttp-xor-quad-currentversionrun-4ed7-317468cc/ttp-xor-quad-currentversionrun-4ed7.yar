rule TTP_XOR_QUAD_CurrentVersionRun_4ed7 {
  strings:
    $key_4ed7 = { 1d b8 [2] 39 b6 [2] 12 9a [2] 3c b8 [2] 28 a3 [2] 27 b9 [2] 39 a4 [2] 3b a5 [2] 20 a3 [2] 3c a4 [2] 20 8b }

  condition:
    any of them
}