rule TTP_XOR_QUAD_CurrentVersionRun_35d2 {
  strings:
    $key_35d2 = { 66 bd [2] 42 b3 [2] 69 9f [2] 47 bd [2] 53 a6 [2] 5c bc [2] 42 a1 [2] 40 a0 [2] 5b a6 [2] 47 a1 [2] 5b 8e }

  condition:
    any of them
}