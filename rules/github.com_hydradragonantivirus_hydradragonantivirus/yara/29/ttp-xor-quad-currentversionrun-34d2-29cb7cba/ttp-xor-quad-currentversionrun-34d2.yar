rule TTP_XOR_QUAD_CurrentVersionRun_34d2 {
  strings:
    $key_34d2 = { 67 bd [2] 43 b3 [2] 68 9f [2] 46 bd [2] 52 a6 [2] 5d bc [2] 43 a1 [2] 41 a0 [2] 5a a6 [2] 46 a1 [2] 5a 8e }

  condition:
    any of them
}