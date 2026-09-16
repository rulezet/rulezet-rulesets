rule TTP_XOR_QUAD_CurrentVersionRun_a019 {
  strings:
    $key_a019 = { f3 76 [2] d7 78 [2] fc 54 [2] d2 76 [2] c6 6d [2] c9 77 [2] d7 6a [2] d5 6b [2] ce 6d [2] d2 6a [2] ce 45 }

  condition:
    any of them
}