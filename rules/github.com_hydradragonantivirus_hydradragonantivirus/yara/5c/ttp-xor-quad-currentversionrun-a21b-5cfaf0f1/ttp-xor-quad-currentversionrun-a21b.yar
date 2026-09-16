rule TTP_XOR_QUAD_CurrentVersionRun_a21b {
  strings:
    $key_a21b = { f1 74 [2] d5 7a [2] fe 56 [2] d0 74 [2] c4 6f [2] cb 75 [2] d5 68 [2] d7 69 [2] cc 6f [2] d0 68 [2] cc 47 }

  condition:
    any of them
}