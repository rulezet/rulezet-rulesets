rule TTP_XOR_QUAD_CurrentVersionRun_a059 {
  strings:
    $key_a059 = { f3 36 [2] d7 38 [2] fc 14 [2] d2 36 [2] c6 2d [2] c9 37 [2] d7 2a [2] d5 2b [2] ce 2d [2] d2 2a [2] ce 05 }

  condition:
    any of them
}