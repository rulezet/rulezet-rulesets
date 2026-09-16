rule TTP_XOR_QUAD_CurrentVersionRun_a25d {
  strings:
    $key_a25d = { f1 32 [2] d5 3c [2] fe 10 [2] d0 32 [2] c4 29 [2] cb 33 [2] d5 2e [2] d7 2f [2] cc 29 [2] d0 2e [2] cc 01 }

  condition:
    any of them
}