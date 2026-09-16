rule TTP_XOR_QUAD_CurrentVersionRun_0fd5 {
  strings:
    $key_0fd5 = { 5c ba [2] 78 b4 [2] 53 98 [2] 7d ba [2] 69 a1 [2] 66 bb [2] 78 a6 [2] 7a a7 [2] 61 a1 [2] 7d a6 [2] 61 89 }

  condition:
    any of them
}