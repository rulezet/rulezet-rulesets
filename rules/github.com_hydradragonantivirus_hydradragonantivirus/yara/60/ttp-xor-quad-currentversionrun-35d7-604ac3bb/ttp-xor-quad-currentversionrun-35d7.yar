rule TTP_XOR_QUAD_CurrentVersionRun_35d7 {
  strings:
    $key_35d7 = { 66 b8 [2] 42 b6 [2] 69 9a [2] 47 b8 [2] 53 a3 [2] 5c b9 [2] 42 a4 [2] 40 a5 [2] 5b a3 [2] 47 a4 [2] 5b 8b }

  condition:
    any of them
}