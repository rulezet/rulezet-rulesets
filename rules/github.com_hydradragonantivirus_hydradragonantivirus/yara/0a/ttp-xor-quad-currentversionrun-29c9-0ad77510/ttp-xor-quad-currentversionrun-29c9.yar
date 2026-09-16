rule TTP_XOR_QUAD_CurrentVersionRun_29c9 {
  strings:
    $key_29c9 = { 7a a6 [2] 5e a8 [2] 75 84 [2] 5b a6 [2] 4f bd [2] 40 a7 [2] 5e ba [2] 5c bb [2] 47 bd [2] 5b ba [2] 47 95 }

  condition:
    any of them
}