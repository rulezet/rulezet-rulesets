rule TTP_XOR_QUAD_CurrentVersionRun_8961 {
  strings:
    $key_8961 = { da 0e [2] fe 00 [2] d5 2c [2] fb 0e [2] ef 15 [2] e0 0f [2] fe 12 [2] fc 13 [2] e7 15 [2] fb 12 [2] e7 3d }

  condition:
    any of them
}