rule TTP_XOR_QUAD_CurrentVersionRun_63d2 {
  strings:
    $key_63d2 = { 30 bd [2] 14 b3 [2] 3f 9f [2] 11 bd [2] 05 a6 [2] 0a bc [2] 14 a1 [2] 16 a0 [2] 0d a6 [2] 11 a1 [2] 0d 8e }

  condition:
    any of them
}