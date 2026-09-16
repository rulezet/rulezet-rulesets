rule TTP_XOR_QUAD_CurrentVersionRun_a206 {
  strings:
    $key_a206 = { f1 69 [2] d5 67 [2] fe 4b [2] d0 69 [2] c4 72 [2] cb 68 [2] d5 75 [2] d7 74 [2] cc 72 [2] d0 75 [2] cc 5a }

  condition:
    any of them
}