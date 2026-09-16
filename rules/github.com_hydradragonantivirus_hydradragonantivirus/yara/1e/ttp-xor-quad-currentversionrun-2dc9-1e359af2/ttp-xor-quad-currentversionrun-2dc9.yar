rule TTP_XOR_QUAD_CurrentVersionRun_2dc9 {
  strings:
    $key_2dc9 = { 7e a6 [2] 5a a8 [2] 71 84 [2] 5f a6 [2] 4b bd [2] 44 a7 [2] 5a ba [2] 58 bb [2] 43 bd [2] 5f ba [2] 43 95 }

  condition:
    any of them
}