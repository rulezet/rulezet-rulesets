rule TTP_XOR_QUAD_CurrentVersionRun_a20e {
  strings:
    $key_a20e = { f1 61 [2] d5 6f [2] fe 43 [2] d0 61 [2] c4 7a [2] cb 60 [2] d5 7d [2] d7 7c [2] cc 7a [2] d0 7d [2] cc 52 }

  condition:
    any of them
}