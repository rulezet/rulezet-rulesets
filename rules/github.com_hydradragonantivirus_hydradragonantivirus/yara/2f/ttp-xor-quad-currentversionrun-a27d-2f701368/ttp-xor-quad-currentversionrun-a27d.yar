rule TTP_XOR_QUAD_CurrentVersionRun_a27d {
  strings:
    $key_a27d = { f1 12 [2] d5 1c [2] fe 30 [2] d0 12 [2] c4 09 [2] cb 13 [2] d5 0e [2] d7 0f [2] cc 09 [2] d0 0e [2] cc 21 }

  condition:
    any of them
}