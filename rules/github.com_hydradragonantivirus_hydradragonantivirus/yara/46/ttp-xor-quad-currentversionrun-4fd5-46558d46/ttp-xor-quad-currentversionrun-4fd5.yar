rule TTP_XOR_QUAD_CurrentVersionRun_4fd5 {
  strings:
    $key_4fd5 = { 1c ba [2] 38 b4 [2] 13 98 [2] 3d ba [2] 29 a1 [2] 26 bb [2] 38 a6 [2] 3a a7 [2] 21 a1 [2] 3d a6 [2] 21 89 }

  condition:
    any of them
}