rule TTP_XOR_QUAD_CurrentVersionRun_5cd2 {
  strings:
    $key_5cd2 = { 0f bd [2] 2b b3 [2] 00 9f [2] 2e bd [2] 3a a6 [2] 35 bc [2] 2b a1 [2] 29 a0 [2] 32 a6 [2] 2e a1 [2] 32 8e }

  condition:
    any of them
}