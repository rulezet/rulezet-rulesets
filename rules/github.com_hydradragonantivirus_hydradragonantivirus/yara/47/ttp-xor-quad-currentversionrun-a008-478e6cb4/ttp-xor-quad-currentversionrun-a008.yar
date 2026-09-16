rule TTP_XOR_QUAD_CurrentVersionRun_a008 {
  strings:
    $key_a008 = { f3 67 [2] d7 69 [2] fc 45 [2] d2 67 [2] c6 7c [2] c9 66 [2] d7 7b [2] d5 7a [2] ce 7c [2] d2 7b [2] ce 54 }

  condition:
    any of them
}