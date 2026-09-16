rule TTP_XOR_QUAD_CurrentVersionRun_a075 {
  strings:
    $key_a075 = { f3 1a [2] d7 14 [2] fc 38 [2] d2 1a [2] c6 01 [2] c9 1b [2] d7 06 [2] d5 07 [2] ce 01 [2] d2 06 [2] ce 29 }

  condition:
    any of them
}