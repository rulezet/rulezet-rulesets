rule TTP_XOR_QUAD_CurrentVersionRun_f4d2 {
  strings:
    $key_f4d2 = { a7 bd [2] 83 b3 [2] a8 9f [2] 86 bd [2] 92 a6 [2] 9d bc [2] 83 a1 [2] 81 a0 [2] 9a a6 [2] 86 a1 [2] 9a 8e }

  condition:
    any of them
}