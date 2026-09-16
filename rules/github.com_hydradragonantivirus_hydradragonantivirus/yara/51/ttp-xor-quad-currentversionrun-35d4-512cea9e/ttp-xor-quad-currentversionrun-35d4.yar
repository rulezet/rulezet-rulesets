rule TTP_XOR_QUAD_CurrentVersionRun_35d4 {
  strings:
    $key_35d4 = { 66 bb [2] 42 b5 [2] 69 99 [2] 47 bb [2] 53 a0 [2] 5c ba [2] 42 a7 [2] 40 a6 [2] 5b a0 [2] 47 a7 [2] 5b 88 }

  condition:
    any of them
}