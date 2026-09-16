rule TTP_XOR_QUAD_CurrentVersionRun_01c8 {
  strings:
    $key_01c8 = { 52 a7 [2] 76 a9 [2] 5d 85 [2] 73 a7 [2] 67 bc [2] 68 a6 [2] 76 bb [2] 74 ba [2] 6f bc [2] 73 bb [2] 6f 94 }

  condition:
    any of them
}