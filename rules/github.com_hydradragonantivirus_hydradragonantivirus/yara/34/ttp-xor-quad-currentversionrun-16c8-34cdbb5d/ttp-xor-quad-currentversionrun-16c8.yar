rule TTP_XOR_QUAD_CurrentVersionRun_16c8 {
  strings:
    $key_16c8 = { 45 a7 [2] 61 a9 [2] 4a 85 [2] 64 a7 [2] 70 bc [2] 7f a6 [2] 61 bb [2] 63 ba [2] 78 bc [2] 64 bb [2] 78 94 }

  condition:
    any of them
}