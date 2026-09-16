rule TTP_XOR_QUAD_CurrentVersionRun_8973 {
  strings:
    $key_8973 = { da 1c [2] fe 12 [2] d5 3e [2] fb 1c [2] ef 07 [2] e0 1d [2] fe 00 [2] fc 01 [2] e7 07 [2] fb 00 [2] e7 2f }

  condition:
    any of them
}