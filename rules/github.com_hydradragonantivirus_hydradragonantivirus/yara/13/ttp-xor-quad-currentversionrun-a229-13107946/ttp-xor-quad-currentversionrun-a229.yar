rule TTP_XOR_QUAD_CurrentVersionRun_a229 {
  strings:
    $key_a229 = { f1 46 [2] d5 48 [2] fe 64 [2] d0 46 [2] c4 5d [2] cb 47 [2] d5 5a [2] d7 5b [2] cc 5d [2] d0 5a [2] cc 75 }

  condition:
    any of them
}