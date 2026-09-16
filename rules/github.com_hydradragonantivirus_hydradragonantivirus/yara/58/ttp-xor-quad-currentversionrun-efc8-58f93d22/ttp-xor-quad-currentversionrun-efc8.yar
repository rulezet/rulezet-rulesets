rule TTP_XOR_QUAD_CurrentVersionRun_efc8 {
  strings:
    $key_efc8 = { bc a7 [2] 98 a9 [2] b3 85 [2] 9d a7 [2] 89 bc [2] 86 a6 [2] 98 bb [2] 9a ba [2] 81 bc [2] 9d bb [2] 81 94 }

  condition:
    any of them
}