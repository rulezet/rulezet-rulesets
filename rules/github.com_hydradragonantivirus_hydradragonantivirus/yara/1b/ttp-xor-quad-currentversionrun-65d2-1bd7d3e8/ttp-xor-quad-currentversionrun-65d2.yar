rule TTP_XOR_QUAD_CurrentVersionRun_65d2 {
  strings:
    $key_65d2 = { 36 bd [2] 12 b3 [2] 39 9f [2] 17 bd [2] 03 a6 [2] 0c bc [2] 12 a1 [2] 10 a0 [2] 0b a6 [2] 17 a1 [2] 0b 8e }

  condition:
    any of them
}