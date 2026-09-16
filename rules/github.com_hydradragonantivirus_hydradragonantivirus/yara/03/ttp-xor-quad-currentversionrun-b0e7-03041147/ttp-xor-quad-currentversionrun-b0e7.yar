rule TTP_XOR_QUAD_CurrentVersionRun_b0e7 {
  strings:
    $key_b0e7 = { e3 88 [2] c7 86 [2] ec aa [2] c2 88 [2] d6 93 [2] d9 89 [2] c7 94 [2] c5 95 [2] de 93 [2] c2 94 [2] de bb }

  condition:
    any of them
}