rule TTP_XOR_QUAD_CurrentVersionRun_895f {
  strings:
    $key_895f = { da 30 [2] fe 3e [2] d5 12 [2] fb 30 [2] ef 2b [2] e0 31 [2] fe 2c [2] fc 2d [2] e7 2b [2] fb 2c [2] e7 03 }

  condition:
    any of them
}