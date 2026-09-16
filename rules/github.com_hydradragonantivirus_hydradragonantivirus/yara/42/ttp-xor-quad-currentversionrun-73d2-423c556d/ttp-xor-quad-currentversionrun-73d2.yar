rule TTP_XOR_QUAD_CurrentVersionRun_73d2 {
  strings:
    $key_73d2 = { 20 bd [2] 04 b3 [2] 2f 9f [2] 01 bd [2] 15 a6 [2] 1a bc [2] 04 a1 [2] 06 a0 [2] 1d a6 [2] 01 a1 [2] 1d 8e }

  condition:
    any of them
}