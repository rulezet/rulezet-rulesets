rule TTP_XOR_QUAD_CurrentVersionRun_a034 {
  strings:
    $key_a034 = { f3 5b [2] d7 55 [2] fc 79 [2] d2 5b [2] c6 40 [2] c9 5a [2] d7 47 [2] d5 46 [2] ce 40 [2] d2 47 [2] ce 68 }

  condition:
    any of them
}