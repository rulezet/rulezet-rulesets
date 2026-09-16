rule TTP_XOR_QUAD_CurrentVersionRun_6cd2 {
  strings:
    $key_6cd2 = { 3f bd [2] 1b b3 [2] 30 9f [2] 1e bd [2] 0a a6 [2] 05 bc [2] 1b a1 [2] 19 a0 [2] 02 a6 [2] 1e a1 [2] 02 8e }

  condition:
    any of them
}