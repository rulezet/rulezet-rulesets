rule TTP_XOR_QUAD_CurrentVersionRun_57d2 {
  strings:
    $key_57d2 = { 04 bd [2] 20 b3 [2] 0b 9f [2] 25 bd [2] 31 a6 [2] 3e bc [2] 20 a1 [2] 22 a0 [2] 39 a6 [2] 25 a1 [2] 39 8e }

  condition:
    any of them
}