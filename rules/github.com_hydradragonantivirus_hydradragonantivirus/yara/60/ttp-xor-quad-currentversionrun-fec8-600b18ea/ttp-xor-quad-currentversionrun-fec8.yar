rule TTP_XOR_QUAD_CurrentVersionRun_fec8 {
  strings:
    $key_fec8 = { ad a7 [2] 89 a9 [2] a2 85 [2] 8c a7 [2] 98 bc [2] 97 a6 [2] 89 bb [2] 8b ba [2] 90 bc [2] 8c bb [2] 90 94 }

  condition:
    any of them
}