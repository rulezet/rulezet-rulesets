rule TTP_XOR_QUAD_CurrentVersionRun_7ed7 {
  strings:
    $key_7ed7 = { 2d b8 [2] 09 b6 [2] 22 9a [2] 0c b8 [2] 18 a3 [2] 17 b9 [2] 09 a4 [2] 0b a5 [2] 10 a3 [2] 0c a4 [2] 10 8b }

  condition:
    any of them
}