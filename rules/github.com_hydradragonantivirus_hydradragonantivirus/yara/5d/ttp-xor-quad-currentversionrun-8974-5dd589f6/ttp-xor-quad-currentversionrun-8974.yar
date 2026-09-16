rule TTP_XOR_QUAD_CurrentVersionRun_8974 {
  strings:
    $key_8974 = { da 1b [2] fe 15 [2] d5 39 [2] fb 1b [2] ef 00 [2] e0 1a [2] fe 07 [2] fc 06 [2] e7 00 [2] fb 07 [2] e7 28 }

  condition:
    any of them
}