rule TTP_XOR_QUAD_CurrentVersionRun_52d2 {
  strings:
    $key_52d2 = { 01 bd [2] 25 b3 [2] 0e 9f [2] 20 bd [2] 34 a6 [2] 3b bc [2] 25 a1 [2] 27 a0 [2] 3c a6 [2] 20 a1 [2] 3c 8e }

  condition:
    any of them
}