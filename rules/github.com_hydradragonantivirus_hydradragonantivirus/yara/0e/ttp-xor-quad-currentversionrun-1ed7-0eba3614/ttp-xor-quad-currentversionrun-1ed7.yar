rule TTP_XOR_QUAD_CurrentVersionRun_1ed7 {
  strings:
    $key_1ed7 = { 4d b8 [2] 69 b6 [2] 42 9a [2] 6c b8 [2] 78 a3 [2] 77 b9 [2] 69 a4 [2] 6b a5 [2] 70 a3 [2] 6c a4 [2] 70 8b }

  condition:
    any of them
}