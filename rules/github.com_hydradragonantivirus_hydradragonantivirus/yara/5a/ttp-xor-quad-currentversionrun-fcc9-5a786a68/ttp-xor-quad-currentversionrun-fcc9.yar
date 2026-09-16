rule TTP_XOR_QUAD_CurrentVersionRun_fcc9 {
  strings:
    $key_fcc9 = { af a6 [2] 8b a8 [2] a0 84 [2] 8e a6 [2] 9a bd [2] 95 a7 [2] 8b ba [2] 89 bb [2] 92 bd [2] 8e ba [2] 92 95 }

  condition:
    any of them
}