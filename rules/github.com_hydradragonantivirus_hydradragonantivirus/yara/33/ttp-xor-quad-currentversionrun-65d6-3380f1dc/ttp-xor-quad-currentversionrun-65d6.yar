rule TTP_XOR_QUAD_CurrentVersionRun_65d6 {
  strings:
    $key_65d6 = { 36 b9 [2] 12 b7 [2] 39 9b [2] 17 b9 [2] 03 a2 [2] 0c b8 [2] 12 a5 [2] 10 a4 [2] 0b a2 [2] 17 a5 [2] 0b 8a }

  condition:
    any of them
}