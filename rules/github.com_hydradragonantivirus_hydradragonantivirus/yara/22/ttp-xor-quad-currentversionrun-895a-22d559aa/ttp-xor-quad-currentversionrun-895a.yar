rule TTP_XOR_QUAD_CurrentVersionRun_895a {
  strings:
    $key_895a = { da 35 [2] fe 3b [2] d5 17 [2] fb 35 [2] ef 2e [2] e0 34 [2] fe 29 [2] fc 28 [2] e7 2e [2] fb 29 [2] e7 06 }

  condition:
    any of them
}