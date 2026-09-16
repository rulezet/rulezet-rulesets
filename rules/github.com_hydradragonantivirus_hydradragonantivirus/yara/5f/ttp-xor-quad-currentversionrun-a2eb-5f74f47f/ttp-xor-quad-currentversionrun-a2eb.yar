rule TTP_XOR_QUAD_CurrentVersionRun_a2eb {
  strings:
    $key_a2eb = { f1 84 [2] d5 8a [2] fe a6 [2] d0 84 [2] c4 9f [2] cb 85 [2] d5 98 [2] d7 99 [2] cc 9f [2] d0 98 [2] cc b7 }

  condition:
    any of them
}