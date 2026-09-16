rule TTP_XOR_QUAD_CurrentVersionRun_894f {
  strings:
    $key_894f = { da 20 [2] fe 2e [2] d5 02 [2] fb 20 [2] ef 3b [2] e0 21 [2] fe 3c [2] fc 3d [2] e7 3b [2] fb 3c [2] e7 13 }

  condition:
    any of them
}