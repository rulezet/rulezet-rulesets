rule TTP_XOR_QUAD_CurrentVersionRun_a51a {
  strings:
    $key_a51a = { f6 75 [2] d2 7b [2] f9 57 [2] d7 75 [2] c3 6e [2] cc 74 [2] d2 69 [2] d0 68 [2] cb 6e [2] d7 69 [2] cb 46 }

  condition:
    any of them
}