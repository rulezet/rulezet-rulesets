rule TTP_XOR_QUAD_CurrentVersionRun_35c9 {
  strings:
    $key_35c9 = { 66 a6 [2] 42 a8 [2] 69 84 [2] 47 a6 [2] 53 bd [2] 5c a7 [2] 42 ba [2] 40 bb [2] 5b bd [2] 47 ba [2] 5b 95 }

  condition:
    any of them
}