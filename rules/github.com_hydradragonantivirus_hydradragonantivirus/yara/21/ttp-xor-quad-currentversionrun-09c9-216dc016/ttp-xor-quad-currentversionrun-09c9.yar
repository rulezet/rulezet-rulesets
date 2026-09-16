rule TTP_XOR_QUAD_CurrentVersionRun_09c9 {
  strings:
    $key_09c9 = { 5a a6 [2] 7e a8 [2] 55 84 [2] 7b a6 [2] 6f bd [2] 60 a7 [2] 7e ba [2] 7c bb [2] 67 bd [2] 7b ba [2] 67 95 }

  condition:
    any of them
}