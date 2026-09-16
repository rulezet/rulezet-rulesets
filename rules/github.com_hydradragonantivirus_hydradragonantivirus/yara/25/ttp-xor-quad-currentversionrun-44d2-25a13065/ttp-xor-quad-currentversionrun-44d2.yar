rule TTP_XOR_QUAD_CurrentVersionRun_44d2 {
  strings:
    $key_44d2 = { 17 bd [2] 33 b3 [2] 18 9f [2] 36 bd [2] 22 a6 [2] 2d bc [2] 33 a1 [2] 31 a0 [2] 2a a6 [2] 36 a1 [2] 2a 8e }

  condition:
    any of them
}