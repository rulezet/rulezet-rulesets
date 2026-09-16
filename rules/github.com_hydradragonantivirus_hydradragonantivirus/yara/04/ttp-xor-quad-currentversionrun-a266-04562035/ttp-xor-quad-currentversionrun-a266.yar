rule TTP_XOR_QUAD_CurrentVersionRun_a266 {
  strings:
    $key_a266 = { f1 09 [2] d5 07 [2] fe 2b [2] d0 09 [2] c4 12 [2] cb 08 [2] d5 15 [2] d7 14 [2] cc 12 [2] d0 15 [2] cc 3a }

  condition:
    any of them
}