rule TTP_XOR_QUAD_CurrentVersionRun_a249 {
  strings:
    $key_a249 = { f1 26 [2] d5 28 [2] fe 04 [2] d0 26 [2] c4 3d [2] cb 27 [2] d5 3a [2] d7 3b [2] cc 3d [2] d0 3a [2] cc 15 }

  condition:
    any of them
}