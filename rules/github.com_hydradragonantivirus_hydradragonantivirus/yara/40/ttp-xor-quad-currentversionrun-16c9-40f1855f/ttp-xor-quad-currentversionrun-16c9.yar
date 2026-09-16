rule TTP_XOR_QUAD_CurrentVersionRun_16c9 {
  strings:
    $key_16c9 = { 45 a6 [2] 61 a8 [2] 4a 84 [2] 64 a6 [2] 70 bd [2] 7f a7 [2] 61 ba [2] 63 bb [2] 78 bd [2] 64 ba [2] 78 95 }

  condition:
    any of them
}