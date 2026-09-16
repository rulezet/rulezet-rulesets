rule TTP_XOR_QUAD_CurrentVersionRun_8969 {
  strings:
    $key_8969 = { da 06 [2] fe 08 [2] d5 24 [2] fb 06 [2] ef 1d [2] e0 07 [2] fe 1a [2] fc 1b [2] e7 1d [2] fb 1a [2] e7 35 }

  condition:
    any of them
}