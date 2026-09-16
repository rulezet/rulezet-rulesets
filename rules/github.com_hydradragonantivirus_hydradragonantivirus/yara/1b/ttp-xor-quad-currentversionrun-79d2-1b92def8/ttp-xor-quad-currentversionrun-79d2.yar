rule TTP_XOR_QUAD_CurrentVersionRun_79d2 {
  strings:
    $key_79d2 = { 2a bd [2] 0e b3 [2] 25 9f [2] 0b bd [2] 1f a6 [2] 10 bc [2] 0e a1 [2] 0c a0 [2] 17 a6 [2] 0b a1 [2] 17 8e }

  condition:
    any of them
}