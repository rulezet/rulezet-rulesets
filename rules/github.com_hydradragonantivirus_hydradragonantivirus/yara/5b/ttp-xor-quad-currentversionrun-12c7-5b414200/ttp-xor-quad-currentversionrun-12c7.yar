rule TTP_XOR_QUAD_CurrentVersionRun_12c7 {
  strings:
    $key_12c7 = { 41 a8 [2] 65 a6 [2] 4e 8a [2] 60 a8 [2] 74 b3 [2] 7b a9 [2] 65 b4 [2] 67 b5 [2] 7c b3 [2] 60 b4 [2] 7c 9b }

  condition:
    any of them
}