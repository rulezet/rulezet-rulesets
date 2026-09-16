rule TTP_XOR_QUAD_CurrentVersionRun_3bc8 {
  strings:
    $key_3bc8 = { 68 a7 [2] 4c a9 [2] 67 85 [2] 49 a7 [2] 5d bc [2] 52 a6 [2] 4c bb [2] 4e ba [2] 55 bc [2] 49 bb [2] 55 94 }

  condition:
    any of them
}