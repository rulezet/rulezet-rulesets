rule TTP_XOR_QUAD_CurrentVersionRun_f8d2 {
  strings:
    $key_f8d2 = { ab bd [2] 8f b3 [2] a4 9f [2] 8a bd [2] 9e a6 [2] 91 bc [2] 8f a1 [2] 8d a0 [2] 96 a6 [2] 8a a1 [2] 96 8e }

  condition:
    any of them
}