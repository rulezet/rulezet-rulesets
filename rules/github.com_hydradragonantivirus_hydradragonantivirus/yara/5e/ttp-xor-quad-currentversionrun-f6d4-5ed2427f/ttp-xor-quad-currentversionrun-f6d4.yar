rule TTP_XOR_QUAD_CurrentVersionRun_f6d4 {
  strings:
    $key_f6d4 = { a5 bb [2] 81 b5 [2] aa 99 [2] 84 bb [2] 90 a0 [2] 9f ba [2] 81 a7 [2] 83 a6 [2] 98 a0 [2] 84 a7 [2] 98 88 }

  condition:
    any of them
}