rule TTP_XOR_QUAD_CurrentVersionRun_a23b {
  strings:
    $key_a23b = { f1 54 [2] d5 5a [2] fe 76 [2] d0 54 [2] c4 4f [2] cb 55 [2] d5 48 [2] d7 49 [2] cc 4f [2] d0 48 [2] cc 67 }

  condition:
    any of them
}