rule TTP_XOR_QUAD_CurrentVersionRun_3ed5 {
  strings:
    $key_3ed5 = { 6d ba [2] 49 b4 [2] 62 98 [2] 4c ba [2] 58 a1 [2] 57 bb [2] 49 a6 [2] 4b a7 [2] 50 a1 [2] 4c a6 [2] 50 89 }

  condition:
    any of them
}