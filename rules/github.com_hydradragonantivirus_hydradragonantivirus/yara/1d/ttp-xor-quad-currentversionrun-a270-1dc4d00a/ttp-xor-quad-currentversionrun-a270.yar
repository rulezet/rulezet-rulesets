rule TTP_XOR_QUAD_CurrentVersionRun_a270 {
  strings:
    $key_a270 = { f1 1f [2] d5 11 [2] fe 3d [2] d0 1f [2] c4 04 [2] cb 1e [2] d5 03 [2] d7 02 [2] cc 04 [2] d0 03 [2] cc 2c }

  condition:
    any of them
}