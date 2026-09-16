rule TTP_XOR_QUAD_CurrentVersionRun_a039 {
  strings:
    $key_a039 = { f3 56 [2] d7 58 [2] fc 74 [2] d2 56 [2] c6 4d [2] c9 57 [2] d7 4a [2] d5 4b [2] ce 4d [2] d2 4a [2] ce 65 }

  condition:
    any of them
}