rule TTP_XOR_QUAD_CurrentVersionRun_896b {
  strings:
    $key_896b = { da 04 [2] fe 0a [2] d5 26 [2] fb 04 [2] ef 1f [2] e0 05 [2] fe 18 [2] fc 19 [2] e7 1f [2] fb 18 [2] e7 37 }

  condition:
    any of them
}