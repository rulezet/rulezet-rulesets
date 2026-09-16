rule TTP_XOR_QUAD_CurrentVersionRun_a2c4 {
  strings:
    $key_a2c4 = { f1 ab [2] d5 a5 [2] fe 89 [2] d0 ab [2] c4 b0 [2] cb aa [2] d5 b7 [2] d7 b6 [2] cc b0 [2] d0 b7 [2] cc 98 }

  condition:
    any of them
}