rule TTP_XOR_QUAD_CurrentVersionRun_890b {
  strings:
    $key_890b = { da 64 [2] fe 6a [2] d5 46 [2] fb 64 [2] ef 7f [2] e0 65 [2] fe 78 [2] fc 79 [2] e7 7f [2] fb 78 [2] e7 57 }

  condition:
    any of them
}