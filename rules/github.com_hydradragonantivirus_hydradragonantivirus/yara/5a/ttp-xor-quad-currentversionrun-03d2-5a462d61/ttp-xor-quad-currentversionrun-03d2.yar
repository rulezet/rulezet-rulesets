rule TTP_XOR_QUAD_CurrentVersionRun_03d2 {
  strings:
    $key_03d2 = { 50 bd [2] 74 b3 [2] 5f 9f [2] 71 bd [2] 65 a6 [2] 6a bc [2] 74 a1 [2] 76 a0 [2] 6d a6 [2] 71 a1 [2] 6d 8e }

  condition:
    any of them
}