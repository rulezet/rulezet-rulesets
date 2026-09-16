rule TTP_XOR_QUAD_CurrentVersionRun_35c7 {
  strings:
    $key_35c7 = { 66 a8 [2] 42 a6 [2] 69 8a [2] 47 a8 [2] 53 b3 [2] 5c a9 [2] 42 b4 [2] 40 b5 [2] 5b b3 [2] 47 b4 [2] 5b 9b }

  condition:
    any of them
}