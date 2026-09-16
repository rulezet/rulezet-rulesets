rule TTP_XOR_QUAD_CurrentVersionRun_32d4 {
  strings:
    $key_32d4 = { 61 bb [2] 45 b5 [2] 6e 99 [2] 40 bb [2] 54 a0 [2] 5b ba [2] 45 a7 [2] 47 a6 [2] 5c a0 [2] 40 a7 [2] 5c 88 }

  condition:
    any of them
}