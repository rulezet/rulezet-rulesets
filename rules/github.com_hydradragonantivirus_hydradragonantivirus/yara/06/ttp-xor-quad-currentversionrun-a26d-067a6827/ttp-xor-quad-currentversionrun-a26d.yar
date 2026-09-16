rule TTP_XOR_QUAD_CurrentVersionRun_a26d {
  strings:
    $key_a26d = { f1 02 [2] d5 0c [2] fe 20 [2] d0 02 [2] c4 19 [2] cb 03 [2] d5 1e [2] d7 1f [2] cc 19 [2] d0 1e [2] cc 31 }

  condition:
    any of them
}