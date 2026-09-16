rule TTP_XOR_QUAD_CurrentVersionRun_41d2 {
  strings:
    $key_41d2 = { 12 bd [2] 36 b3 [2] 1d 9f [2] 33 bd [2] 27 a6 [2] 28 bc [2] 36 a1 [2] 34 a0 [2] 2f a6 [2] 33 a1 [2] 2f 8e }

  condition:
    any of them
}