rule TTP_XOR_QUAD_CurrentVersionRun_b0d7 {
  strings:
    $key_b0d7 = { e3 b8 [2] c7 b6 [2] ec 9a [2] c2 b8 [2] d6 a3 [2] d9 b9 [2] c7 a4 [2] c5 a5 [2] de a3 [2] c2 a4 [2] de 8b }

  condition:
    any of them
}