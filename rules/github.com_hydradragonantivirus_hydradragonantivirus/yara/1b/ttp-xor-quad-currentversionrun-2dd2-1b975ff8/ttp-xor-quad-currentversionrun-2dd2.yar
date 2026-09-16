rule TTP_XOR_QUAD_CurrentVersionRun_2dd2 {
  strings:
    $key_2dd2 = { 7e bd [2] 5a b3 [2] 71 9f [2] 5f bd [2] 4b a6 [2] 44 bc [2] 5a a1 [2] 58 a0 [2] 43 a6 [2] 5f a1 [2] 43 8e }

  condition:
    any of them
}