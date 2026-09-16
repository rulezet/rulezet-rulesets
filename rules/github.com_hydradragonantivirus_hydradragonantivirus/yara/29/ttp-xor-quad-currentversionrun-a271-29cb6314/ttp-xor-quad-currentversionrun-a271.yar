rule TTP_XOR_QUAD_CurrentVersionRun_a271 {
  strings:
    $key_a271 = { f1 1e [2] d5 10 [2] fe 3c [2] d0 1e [2] c4 05 [2] cb 1f [2] d5 02 [2] d7 03 [2] cc 05 [2] d0 02 [2] cc 2d }

  condition:
    any of them
}