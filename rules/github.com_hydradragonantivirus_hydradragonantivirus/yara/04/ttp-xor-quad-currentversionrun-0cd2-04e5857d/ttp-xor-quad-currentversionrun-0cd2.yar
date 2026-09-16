rule TTP_XOR_QUAD_CurrentVersionRun_0cd2 {
  strings:
    $key_0cd2 = { 5f bd [2] 7b b3 [2] 50 9f [2] 7e bd [2] 6a a6 [2] 65 bc [2] 7b a1 [2] 79 a0 [2] 62 a6 [2] 7e a1 [2] 62 8e }

  condition:
    any of them
}