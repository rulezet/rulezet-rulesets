rule TTP_XOR_QUAD_CurrentVersionRun_1cd2 {
  strings:
    $key_1cd2 = { 4f bd [2] 6b b3 [2] 40 9f [2] 6e bd [2] 7a a6 [2] 75 bc [2] 6b a1 [2] 69 a0 [2] 72 a6 [2] 6e a1 [2] 72 8e }

  condition:
    any of them
}