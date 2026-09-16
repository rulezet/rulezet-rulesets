rule TTP_XOR_QUAD_CurrentVersionRun_75d2 {
  strings:
    $key_75d2 = { 26 bd [2] 02 b3 [2] 29 9f [2] 07 bd [2] 13 a6 [2] 1c bc [2] 02 a1 [2] 00 a0 [2] 1b a6 [2] 07 a1 [2] 1b 8e }

  condition:
    any of them
}