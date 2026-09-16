rule TTP_XOR_QUAD_CurrentVersionRun_a23e {
  strings:
    $key_a23e = { f1 51 [2] d5 5f [2] fe 73 [2] d0 51 [2] c4 4a [2] cb 50 [2] d5 4d [2] d7 4c [2] cc 4a [2] d0 4d [2] cc 62 }

  condition:
    any of them
}