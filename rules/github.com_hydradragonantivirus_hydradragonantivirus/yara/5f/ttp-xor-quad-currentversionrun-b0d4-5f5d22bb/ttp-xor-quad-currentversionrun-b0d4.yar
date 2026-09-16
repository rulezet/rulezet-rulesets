rule TTP_XOR_QUAD_CurrentVersionRun_b0d4 {
  strings:
    $key_b0d4 = { e3 bb [2] c7 b5 [2] ec 99 [2] c2 bb [2] d6 a0 [2] d9 ba [2] c7 a7 [2] c5 a6 [2] de a0 [2] c2 a7 [2] de 88 }

  condition:
    any of them
}