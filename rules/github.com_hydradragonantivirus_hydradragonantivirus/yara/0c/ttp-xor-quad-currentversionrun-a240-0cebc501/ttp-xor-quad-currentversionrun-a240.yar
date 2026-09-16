rule TTP_XOR_QUAD_CurrentVersionRun_a240 {
  strings:
    $key_a240 = { f1 2f [2] d5 21 [2] fe 0d [2] d0 2f [2] c4 34 [2] cb 2e [2] d5 33 [2] d7 32 [2] cc 34 [2] d0 33 [2] cc 1c }

  condition:
    any of them
}