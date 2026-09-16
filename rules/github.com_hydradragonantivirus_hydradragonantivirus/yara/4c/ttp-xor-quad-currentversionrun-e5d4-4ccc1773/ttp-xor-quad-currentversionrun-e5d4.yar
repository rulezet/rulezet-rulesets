rule TTP_XOR_QUAD_CurrentVersionRun_e5d4 {
  strings:
    $key_e5d4 = { b6 bb [2] 92 b5 [2] b9 99 [2] 97 bb [2] 83 a0 [2] 8c ba [2] 92 a7 [2] 90 a6 [2] 8b a0 [2] 97 a7 [2] 8b 88 }

  condition:
    any of them
}