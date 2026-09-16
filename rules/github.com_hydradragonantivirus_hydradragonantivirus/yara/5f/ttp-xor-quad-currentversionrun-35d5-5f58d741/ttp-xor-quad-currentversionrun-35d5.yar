rule TTP_XOR_QUAD_CurrentVersionRun_35d5 {
  strings:
    $key_35d5 = { 66 ba [2] 42 b4 [2] 69 98 [2] 47 ba [2] 53 a1 [2] 5c bb [2] 42 a6 [2] 40 a7 [2] 5b a1 [2] 47 a6 [2] 5b 89 }

  condition:
    any of them
}