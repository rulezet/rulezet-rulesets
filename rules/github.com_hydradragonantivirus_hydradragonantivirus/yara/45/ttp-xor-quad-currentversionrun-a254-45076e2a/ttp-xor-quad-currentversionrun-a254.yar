rule TTP_XOR_QUAD_CurrentVersionRun_a254 {
  strings:
    $key_a254 = { f1 3b [2] d5 35 [2] fe 19 [2] d0 3b [2] c4 20 [2] cb 3a [2] d5 27 [2] d7 26 [2] cc 20 [2] d0 27 [2] cc 08 }

  condition:
    any of them
}