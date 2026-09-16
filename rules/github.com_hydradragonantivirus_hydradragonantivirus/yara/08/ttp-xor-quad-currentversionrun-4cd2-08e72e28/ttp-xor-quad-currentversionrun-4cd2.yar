rule TTP_XOR_QUAD_CurrentVersionRun_4cd2 {
  strings:
    $key_4cd2 = { 1f bd [2] 3b b3 [2] 10 9f [2] 3e bd [2] 2a a6 [2] 25 bc [2] 3b a1 [2] 39 a0 [2] 22 a6 [2] 3e a1 [2] 22 8e }

  condition:
    any of them
}