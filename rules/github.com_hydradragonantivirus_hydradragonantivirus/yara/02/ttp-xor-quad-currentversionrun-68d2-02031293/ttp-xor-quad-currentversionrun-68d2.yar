rule TTP_XOR_QUAD_CurrentVersionRun_68d2 {
  strings:
    $key_68d2 = { 3b bd [2] 1f b3 [2] 34 9f [2] 1a bd [2] 0e a6 [2] 01 bc [2] 1f a1 [2] 1d a0 [2] 06 a6 [2] 1a a1 [2] 06 8e }

  condition:
    any of them
}