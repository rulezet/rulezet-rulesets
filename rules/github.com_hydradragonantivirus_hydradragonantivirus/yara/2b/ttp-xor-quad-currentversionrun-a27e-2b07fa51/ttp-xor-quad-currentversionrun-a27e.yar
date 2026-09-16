rule TTP_XOR_QUAD_CurrentVersionRun_a27e {
  strings:
    $key_a27e = { f1 11 [2] d5 1f [2] fe 33 [2] d0 11 [2] c4 0a [2] cb 10 [2] d5 0d [2] d7 0c [2] cc 0a [2] d0 0d [2] cc 22 }

  condition:
    any of them
}