rule TTP_XOR_QUAD_CurrentVersionRun_4fc8 {
  strings:
    $key_4fc8 = { 1c a7 [2] 38 a9 [2] 13 85 [2] 3d a7 [2] 29 bc [2] 26 a6 [2] 38 bb [2] 3a ba [2] 21 bc [2] 3d bb [2] 21 94 }

  condition:
    any of them
}