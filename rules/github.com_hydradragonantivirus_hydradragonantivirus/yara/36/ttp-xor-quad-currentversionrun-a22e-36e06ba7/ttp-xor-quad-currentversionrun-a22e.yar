rule TTP_XOR_QUAD_CurrentVersionRun_a22e {
  strings:
    $key_a22e = { f1 41 [2] d5 4f [2] fe 63 [2] d0 41 [2] c4 5a [2] cb 40 [2] d5 5d [2] d7 5c [2] cc 5a [2] d0 5d [2] cc 72 }

  condition:
    any of them
}