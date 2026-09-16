rule TTP_XOR_QUAD_CurrentVersionRun_895d {
  strings:
    $key_895d = { da 32 [2] fe 3c [2] d5 10 [2] fb 32 [2] ef 29 [2] e0 33 [2] fe 2e [2] fc 2f [2] e7 29 [2] fb 2e [2] e7 01 }

  condition:
    any of them
}