rule TTP_XOR_QUAD_CurrentVersionRun_a2ef {
  strings:
    $key_a2ef = { f1 80 [2] d5 8e [2] fe a2 [2] d0 80 [2] c4 9b [2] cb 81 [2] d5 9c [2] d7 9d [2] cc 9b [2] d0 9c [2] cc b3 }

  condition:
    any of them
}