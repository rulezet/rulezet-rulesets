rule TTP_XOR_QUAD_CurrentVersionRun_a045 {
  strings:
    $key_a045 = { f3 2a [2] d7 24 [2] fc 08 [2] d2 2a [2] c6 31 [2] c9 2b [2] d7 36 [2] d5 37 [2] ce 31 [2] d2 36 [2] ce 19 }

  condition:
    any of them
}