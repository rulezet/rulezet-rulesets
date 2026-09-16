rule TTP_XOR_QUAD_CurrentVersionRun_2cd7 {
  strings:
    $key_2cd7 = { 7f b8 [2] 5b b6 [2] 70 9a [2] 5e b8 [2] 4a a3 [2] 45 b9 [2] 5b a4 [2] 59 a5 [2] 42 a3 [2] 5e a4 [2] 42 8b }

  condition:
    any of them
}