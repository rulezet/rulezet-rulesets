rule TTP_XOR_QUAD_CurrentVersionRun_eec8 {
  strings:
    $key_eec8 = { bd a7 [2] 99 a9 [2] b2 85 [2] 9c a7 [2] 88 bc [2] 87 a6 [2] 99 bb [2] 9b ba [2] 80 bc [2] 9c bb [2] 80 94 }

  condition:
    any of them
}