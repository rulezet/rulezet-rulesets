rule TTP_XOR_QUAD_CurrentVersionRun_ffc8 {
  strings:
    $key_ffc8 = { ac a7 [2] 88 a9 [2] a3 85 [2] 8d a7 [2] 99 bc [2] 96 a6 [2] 88 bb [2] 8a ba [2] 91 bc [2] 8d bb [2] 91 94 }

  condition:
    any of them
}