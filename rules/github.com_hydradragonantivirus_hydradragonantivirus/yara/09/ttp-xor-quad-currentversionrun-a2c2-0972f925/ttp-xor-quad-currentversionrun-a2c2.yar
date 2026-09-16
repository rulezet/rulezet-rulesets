rule TTP_XOR_QUAD_CurrentVersionRun_a2c2 {
  strings:
    $key_a2c2 = { f1 ad [2] d5 a3 [2] fe 8f [2] d0 ad [2] c4 b6 [2] cb ac [2] d5 b1 [2] d7 b0 [2] cc b6 [2] d0 b1 [2] cc 9e }

  condition:
    any of them
}