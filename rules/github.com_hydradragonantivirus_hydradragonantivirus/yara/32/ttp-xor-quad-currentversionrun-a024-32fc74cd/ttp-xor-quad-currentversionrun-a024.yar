rule TTP_XOR_QUAD_CurrentVersionRun_a024 {
  strings:
    $key_a024 = { f3 4b [2] d7 45 [2] fc 69 [2] d2 4b [2] c6 50 [2] c9 4a [2] d7 57 [2] d5 56 [2] ce 50 [2] d2 57 [2] ce 78 }

  condition:
    any of them
}