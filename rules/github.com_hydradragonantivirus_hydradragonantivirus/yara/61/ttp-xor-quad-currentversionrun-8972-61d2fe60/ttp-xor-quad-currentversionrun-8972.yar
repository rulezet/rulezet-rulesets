rule TTP_XOR_QUAD_CurrentVersionRun_8972 {
  strings:
    $key_8972 = { da 1d [2] fe 13 [2] d5 3f [2] fb 1d [2] ef 06 [2] e0 1c [2] fe 01 [2] fc 00 [2] e7 06 [2] fb 01 [2] e7 2e }

  condition:
    any of them
}