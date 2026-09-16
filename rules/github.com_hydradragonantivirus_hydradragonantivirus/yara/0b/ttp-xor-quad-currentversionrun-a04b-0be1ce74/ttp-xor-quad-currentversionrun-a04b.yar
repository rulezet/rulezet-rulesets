rule TTP_XOR_QUAD_CurrentVersionRun_a04b {
  strings:
    $key_a04b = { f3 24 [2] d7 2a [2] fc 06 [2] d2 24 [2] c6 3f [2] c9 25 [2] d7 38 [2] d5 39 [2] ce 3f [2] d2 38 [2] ce 17 }

  condition:
    any of them
}