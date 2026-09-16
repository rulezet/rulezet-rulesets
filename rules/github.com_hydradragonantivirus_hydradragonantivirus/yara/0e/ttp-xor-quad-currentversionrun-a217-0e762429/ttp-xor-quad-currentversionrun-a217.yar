rule TTP_XOR_QUAD_CurrentVersionRun_a217 {
  strings:
    $key_a217 = { f1 78 [2] d5 76 [2] fe 5a [2] d0 78 [2] c4 63 [2] cb 79 [2] d5 64 [2] d7 65 [2] cc 63 [2] d0 64 [2] cc 4b }

  condition:
    any of them
}