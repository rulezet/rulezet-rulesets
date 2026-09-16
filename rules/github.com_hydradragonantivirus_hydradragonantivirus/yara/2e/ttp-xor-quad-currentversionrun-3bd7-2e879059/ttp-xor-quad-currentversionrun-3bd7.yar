rule TTP_XOR_QUAD_CurrentVersionRun_3bd7 {
  strings:
    $key_3bd7 = { 68 b8 [2] 4c b6 [2] 67 9a [2] 49 b8 [2] 5d a3 [2] 52 b9 [2] 4c a4 [2] 4e a5 [2] 55 a3 [2] 49 a4 [2] 55 8b }

  condition:
    any of them
}