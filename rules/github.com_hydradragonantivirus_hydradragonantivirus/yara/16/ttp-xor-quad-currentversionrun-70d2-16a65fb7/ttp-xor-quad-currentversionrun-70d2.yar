rule TTP_XOR_QUAD_CurrentVersionRun_70d2 {
  strings:
    $key_70d2 = { 23 bd [2] 07 b3 [2] 2c 9f [2] 02 bd [2] 16 a6 [2] 19 bc [2] 07 a1 [2] 05 a0 [2] 1e a6 [2] 02 a1 [2] 1e 8e }

  condition:
    any of them
}