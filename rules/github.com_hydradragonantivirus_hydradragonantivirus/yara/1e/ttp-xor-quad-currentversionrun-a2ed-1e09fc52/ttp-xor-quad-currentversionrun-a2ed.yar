rule TTP_XOR_QUAD_CurrentVersionRun_a2ed {
  strings:
    $key_a2ed = { f1 82 [2] d5 8c [2] fe a0 [2] d0 82 [2] c4 99 [2] cb 83 [2] d5 9e [2] d7 9f [2] cc 99 [2] d0 9e [2] cc b1 }

  condition:
    any of them
}