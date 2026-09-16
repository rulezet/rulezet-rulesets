rule TTP_XOR_QUAD_CurrentVersionRun_02d2 {
  strings:
    $key_02d2 = { 51 bd [2] 75 b3 [2] 5e 9f [2] 70 bd [2] 64 a6 [2] 6b bc [2] 75 a1 [2] 77 a0 [2] 6c a6 [2] 70 a1 [2] 6c 8e }

  condition:
    any of them
}