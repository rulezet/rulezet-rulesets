rule TTP_XOR_QUAD_CurrentVersionRun_2ed7 {
  strings:
    $key_2ed7 = { 7d b8 [2] 59 b6 [2] 72 9a [2] 5c b8 [2] 48 a3 [2] 47 b9 [2] 59 a4 [2] 5b a5 [2] 40 a3 [2] 5c a4 [2] 40 8b }

  condition:
    any of them
}