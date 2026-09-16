rule TTP_XOR_QUAD_CurrentVersionRun_66d2 {
  strings:
    $key_66d2 = { 35 bd [2] 11 b3 [2] 3a 9f [2] 14 bd [2] 00 a6 [2] 0f bc [2] 11 a1 [2] 13 a0 [2] 08 a6 [2] 14 a1 [2] 08 8e }

  condition:
    any of them
}