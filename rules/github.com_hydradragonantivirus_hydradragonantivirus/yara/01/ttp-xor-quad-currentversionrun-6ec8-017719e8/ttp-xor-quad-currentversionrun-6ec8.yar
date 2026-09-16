rule TTP_XOR_QUAD_CurrentVersionRun_6ec8 {
  strings:
    $key_6ec8 = { 3d a7 [2] 19 a9 [2] 32 85 [2] 1c a7 [2] 08 bc [2] 07 a6 [2] 19 bb [2] 1b ba [2] 00 bc [2] 1c bb [2] 00 94 }

  condition:
    any of them
}