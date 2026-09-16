rule TTP_XOR_QUAD_CurrentVersionRun_a256 {
  strings:
    $key_a256 = { f1 39 [2] d5 37 [2] fe 1b [2] d0 39 [2] c4 22 [2] cb 38 [2] d5 25 [2] d7 24 [2] cc 22 [2] d0 25 [2] cc 0a }

  condition:
    any of them
}