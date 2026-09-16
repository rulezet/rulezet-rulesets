rule TTP_XOR_QUAD_CurrentVersionRun_894b {
  strings:
    $key_894b = { da 24 [2] fe 2a [2] d5 06 [2] fb 24 [2] ef 3f [2] e0 25 [2] fe 38 [2] fc 39 [2] e7 3f [2] fb 38 [2] e7 17 }

  condition:
    any of them
}