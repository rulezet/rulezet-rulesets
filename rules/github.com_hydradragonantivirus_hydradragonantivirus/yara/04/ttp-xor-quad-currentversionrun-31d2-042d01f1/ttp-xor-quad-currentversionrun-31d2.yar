rule TTP_XOR_QUAD_CurrentVersionRun_31d2 {
  strings:
    $key_31d2 = { 62 bd [2] 46 b3 [2] 6d 9f [2] 43 bd [2] 57 a6 [2] 58 bc [2] 46 a1 [2] 44 a0 [2] 5f a6 [2] 43 a1 [2] 5f 8e }

  condition:
    any of them
}