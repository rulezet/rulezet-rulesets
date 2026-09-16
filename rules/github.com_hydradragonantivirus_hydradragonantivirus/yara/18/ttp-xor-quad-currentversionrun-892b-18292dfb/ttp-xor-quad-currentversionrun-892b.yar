rule TTP_XOR_QUAD_CurrentVersionRun_892b {
  strings:
    $key_892b = { da 44 [2] fe 4a [2] d5 66 [2] fb 44 [2] ef 5f [2] e0 45 [2] fe 58 [2] fc 59 [2] e7 5f [2] fb 58 [2] e7 77 }

  condition:
    any of them
}