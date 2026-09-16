rule TTP_XOR_QUAD_CurrentVersionRun_a2ee {
  strings:
    $key_a2ee = { f1 81 [2] d5 8f [2] fe a3 [2] d0 81 [2] c4 9a [2] cb 80 [2] d5 9d [2] d7 9c [2] cc 9a [2] d0 9d [2] cc b2 }

  condition:
    any of them
}