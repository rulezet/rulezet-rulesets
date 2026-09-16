rule TTP_XOR_QUAD_CurrentVersionRun_47d2 {
  strings:
    $key_47d2 = { 14 bd [2] 30 b3 [2] 1b 9f [2] 35 bd [2] 21 a6 [2] 2e bc [2] 30 a1 [2] 32 a0 [2] 29 a6 [2] 35 a1 [2] 29 8e }

  condition:
    any of them
}