rule TTP_XOR_QUAD_CurrentVersionRun_a224 {
  strings:
    $key_a224 = { f1 4b [2] d5 45 [2] fe 69 [2] d0 4b [2] c4 50 [2] cb 4a [2] d5 57 [2] d7 56 [2] cc 50 [2] d0 57 [2] cc 78 }

  condition:
    any of them
}