rule TTP_XOR_QUAD_CurrentVersionRun_a56a {
  strings:
    $key_a56a = { f6 05 [2] d2 0b [2] f9 27 [2] d7 05 [2] c3 1e [2] cc 04 [2] d2 19 [2] d0 18 [2] cb 1e [2] d7 19 [2] cb 36 }

  condition:
    any of them
}