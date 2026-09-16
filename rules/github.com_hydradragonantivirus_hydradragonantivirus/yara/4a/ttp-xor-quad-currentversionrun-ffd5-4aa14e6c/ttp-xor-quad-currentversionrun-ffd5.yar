rule TTP_XOR_QUAD_CurrentVersionRun_ffd5 {
  strings:
    $key_ffd5 = { ac ba [2] 88 b4 [2] a3 98 [2] 8d ba [2] 99 a1 [2] 96 bb [2] 88 a6 [2] 8a a7 [2] 91 a1 [2] 8d a6 [2] 91 89 }

  condition:
    any of them
}