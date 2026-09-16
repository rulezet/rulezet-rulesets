rule TTP_XOR_QUAD_CurrentVersionRun_b045 {
  strings:
    $key_b045 = { e3 2a [2] c7 24 [2] ec 08 [2] c2 2a [2] d6 31 [2] d9 2b [2] c7 36 [2] c5 37 [2] de 31 [2] c2 36 [2] de 19 }

  condition:
    any of them
}