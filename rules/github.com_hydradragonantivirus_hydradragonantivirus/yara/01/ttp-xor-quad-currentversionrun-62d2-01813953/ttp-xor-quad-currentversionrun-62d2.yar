rule TTP_XOR_QUAD_CurrentVersionRun_62d2 {
  strings:
    $key_62d2 = { 31 bd [2] 15 b3 [2] 3e 9f [2] 10 bd [2] 04 a6 [2] 0b bc [2] 15 a1 [2] 17 a0 [2] 0c a6 [2] 10 a1 [2] 0c 8e }

  condition:
    any of them
}