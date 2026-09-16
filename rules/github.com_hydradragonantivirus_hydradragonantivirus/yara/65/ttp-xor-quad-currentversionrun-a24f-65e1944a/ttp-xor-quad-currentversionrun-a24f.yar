rule TTP_XOR_QUAD_CurrentVersionRun_a24f {
  strings:
    $key_a24f = { f1 20 [2] d5 2e [2] fe 02 [2] d0 20 [2] c4 3b [2] cb 21 [2] d5 3c [2] d7 3d [2] cc 3b [2] d0 3c [2] cc 13 }

  condition:
    any of them
}