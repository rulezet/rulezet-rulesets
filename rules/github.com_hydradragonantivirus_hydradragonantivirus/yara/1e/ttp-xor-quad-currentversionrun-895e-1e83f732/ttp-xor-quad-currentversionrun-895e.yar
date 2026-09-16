rule TTP_XOR_QUAD_CurrentVersionRun_895e {
  strings:
    $key_895e = { da 31 [2] fe 3f [2] d5 13 [2] fb 31 [2] ef 2a [2] e0 30 [2] fe 2d [2] fc 2c [2] e7 2a [2] fb 2d [2] e7 02 }

  condition:
    any of them
}