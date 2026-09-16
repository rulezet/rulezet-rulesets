rule TTP_XOR_QUAD_CurrentVersionRun_b0d5 {
  strings:
    $key_b0d5 = { e3 ba [2] c7 b4 [2] ec 98 [2] c2 ba [2] d6 a1 [2] d9 bb [2] c7 a6 [2] c5 a7 [2] de a1 [2] c2 a6 [2] de 89 }

  condition:
    any of them
}