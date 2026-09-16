rule TTP_XOR_QUAD_CurrentVersionRun_a21a {
  strings:
    $key_a21a = { f1 75 [2] d5 7b [2] fe 57 [2] d0 75 [2] c4 6e [2] cb 74 [2] d5 69 [2] d7 68 [2] cc 6e [2] d0 69 [2] cc 46 }

  condition:
    any of them
}