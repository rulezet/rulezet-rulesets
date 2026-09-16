rule TTP_XOR_QUAD_CurrentVersionRun_64d2 {
  strings:
    $key_64d2 = { 37 bd [2] 13 b3 [2] 38 9f [2] 16 bd [2] 02 a6 [2] 0d bc [2] 13 a1 [2] 11 a0 [2] 0a a6 [2] 16 a1 [2] 0a 8e }

  condition:
    any of them
}