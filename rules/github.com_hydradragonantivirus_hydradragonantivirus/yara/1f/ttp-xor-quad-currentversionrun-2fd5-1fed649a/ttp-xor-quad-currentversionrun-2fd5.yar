rule TTP_XOR_QUAD_CurrentVersionRun_2fd5 {
  strings:
    $key_2fd5 = { 7c ba [2] 58 b4 [2] 73 98 [2] 5d ba [2] 49 a1 [2] 46 bb [2] 58 a6 [2] 5a a7 [2] 41 a1 [2] 5d a6 [2] 41 89 }

  condition:
    any of them
}