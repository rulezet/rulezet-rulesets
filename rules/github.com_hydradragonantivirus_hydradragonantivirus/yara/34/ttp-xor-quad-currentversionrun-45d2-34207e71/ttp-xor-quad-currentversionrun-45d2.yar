rule TTP_XOR_QUAD_CurrentVersionRun_45d2 {
  strings:
    $key_45d2 = { 16 bd [2] 32 b3 [2] 19 9f [2] 37 bd [2] 23 a6 [2] 2c bc [2] 32 a1 [2] 30 a0 [2] 2b a6 [2] 37 a1 [2] 2b 8e }

  condition:
    any of them
}