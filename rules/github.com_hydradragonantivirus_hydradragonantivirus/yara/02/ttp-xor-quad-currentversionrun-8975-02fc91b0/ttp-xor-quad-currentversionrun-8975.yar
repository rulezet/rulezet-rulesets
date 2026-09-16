rule TTP_XOR_QUAD_CurrentVersionRun_8975 {
  strings:
    $key_8975 = { da 1a [2] fe 14 [2] d5 38 [2] fb 1a [2] ef 01 [2] e0 1b [2] fe 06 [2] fc 07 [2] e7 01 [2] fb 06 [2] e7 29 }

  condition:
    any of them
}