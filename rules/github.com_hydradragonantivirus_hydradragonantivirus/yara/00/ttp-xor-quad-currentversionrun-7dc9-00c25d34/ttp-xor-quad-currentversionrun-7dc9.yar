rule TTP_XOR_QUAD_CurrentVersionRun_7dc9 {
  strings:
    $key_7dc9 = { 2e a6 [2] 0a a8 [2] 21 84 [2] 0f a6 [2] 1b bd [2] 14 a7 [2] 0a ba [2] 08 bb [2] 13 bd [2] 0f ba [2] 13 95 }

  condition:
    any of them
}