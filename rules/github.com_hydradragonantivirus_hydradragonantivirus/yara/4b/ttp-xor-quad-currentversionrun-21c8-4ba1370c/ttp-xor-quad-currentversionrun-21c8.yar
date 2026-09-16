rule TTP_XOR_QUAD_CurrentVersionRun_21c8 {
  strings:
    $key_21c8 = { 72 a7 [2] 56 a9 [2] 7d 85 [2] 53 a7 [2] 47 bc [2] 48 a6 [2] 56 bb [2] 54 ba [2] 4f bc [2] 53 bb [2] 4f 94 }

  condition:
    any of them
}