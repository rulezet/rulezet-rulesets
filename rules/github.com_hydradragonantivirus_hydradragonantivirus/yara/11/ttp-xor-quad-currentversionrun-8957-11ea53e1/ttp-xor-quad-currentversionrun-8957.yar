rule TTP_XOR_QUAD_CurrentVersionRun_8957 {
  strings:
    $key_8957 = { da 38 [2] fe 36 [2] d5 1a [2] fb 38 [2] ef 23 [2] e0 39 [2] fe 24 [2] fc 25 [2] e7 23 [2] fb 24 [2] e7 0b }

  condition:
    any of them
}