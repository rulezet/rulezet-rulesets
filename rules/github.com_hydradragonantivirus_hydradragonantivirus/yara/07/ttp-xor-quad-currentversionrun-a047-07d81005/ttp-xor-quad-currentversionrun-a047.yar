rule TTP_XOR_QUAD_CurrentVersionRun_a047 {
  strings:
    $key_a047 = { f3 28 [2] d7 26 [2] fc 0a [2] d2 28 [2] c6 33 [2] c9 29 [2] d7 34 [2] d5 35 [2] ce 33 [2] d2 34 [2] ce 1b }

  condition:
    any of them
}