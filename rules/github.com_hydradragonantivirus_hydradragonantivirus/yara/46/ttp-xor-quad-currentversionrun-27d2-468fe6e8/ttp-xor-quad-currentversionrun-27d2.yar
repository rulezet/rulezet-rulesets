rule TTP_XOR_QUAD_CurrentVersionRun_27d2 {
  strings:
    $key_27d2 = { 74 bd [2] 50 b3 [2] 7b 9f [2] 55 bd [2] 41 a6 [2] 4e bc [2] 50 a1 [2] 52 a0 [2] 49 a6 [2] 55 a1 [2] 49 8e }

  condition:
    any of them
}