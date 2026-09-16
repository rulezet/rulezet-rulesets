rule TTP_XOR_QUAD_CurrentVersionRun_37c9 {
  strings:
    $key_37c9 = { 64 a6 [2] 40 a8 [2] 6b 84 [2] 45 a6 [2] 51 bd [2] 5e a7 [2] 40 ba [2] 42 bb [2] 59 bd [2] 45 ba [2] 59 95 }

  condition:
    any of them
}