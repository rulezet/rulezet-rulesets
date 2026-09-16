rule TTP_XOR_QUAD_CurrentVersionRun_8917 {
  strings:
    $key_8917 = { da 78 [2] fe 76 [2] d5 5a [2] fb 78 [2] ef 63 [2] e0 79 [2] fe 64 [2] fc 65 [2] e7 63 [2] fb 64 [2] e7 4b }

  condition:
    any of them
}