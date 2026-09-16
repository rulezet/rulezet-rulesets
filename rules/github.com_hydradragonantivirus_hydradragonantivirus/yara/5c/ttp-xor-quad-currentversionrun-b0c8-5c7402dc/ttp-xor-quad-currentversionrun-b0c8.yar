rule TTP_XOR_QUAD_CurrentVersionRun_b0c8 {
  strings:
    $key_b0c8 = { e3 a7 [2] c7 a9 [2] ec 85 [2] c2 a7 [2] d6 bc [2] d9 a6 [2] c7 bb [2] c5 ba [2] de bc [2] c2 bb [2] de 94 }

  condition:
    any of them
}