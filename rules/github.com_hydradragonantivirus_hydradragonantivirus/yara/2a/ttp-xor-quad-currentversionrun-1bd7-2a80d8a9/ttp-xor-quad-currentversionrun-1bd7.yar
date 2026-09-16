rule TTP_XOR_QUAD_CurrentVersionRun_1bd7 {
  strings:
    $key_1bd7 = { 48 b8 [2] 6c b6 [2] 47 9a [2] 69 b8 [2] 7d a3 [2] 72 b9 [2] 6c a4 [2] 6e a5 [2] 75 a3 [2] 69 a4 [2] 75 8b }

  condition:
    any of them
}