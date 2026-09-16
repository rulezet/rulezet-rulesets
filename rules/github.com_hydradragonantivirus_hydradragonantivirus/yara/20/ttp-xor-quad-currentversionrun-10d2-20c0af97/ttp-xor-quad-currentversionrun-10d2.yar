rule TTP_XOR_QUAD_CurrentVersionRun_10d2 {
  strings:
    $key_10d2 = { 43 bd [2] 67 b3 [2] 4c 9f [2] 62 bd [2] 76 a6 [2] 79 bc [2] 67 a1 [2] 65 a0 [2] 7e a6 [2] 62 a1 [2] 7e 8e }

  condition:
    any of them
}