rule TTP_XOR_QUAD_CurrentVersionRun_62d4 {
  strings:
    $key_62d4 = { 31 bb [2] 15 b5 [2] 3e 99 [2] 10 bb [2] 04 a0 [2] 0b ba [2] 15 a7 [2] 17 a6 [2] 0c a0 [2] 10 a7 [2] 0c 88 }

  condition:
    any of them
}