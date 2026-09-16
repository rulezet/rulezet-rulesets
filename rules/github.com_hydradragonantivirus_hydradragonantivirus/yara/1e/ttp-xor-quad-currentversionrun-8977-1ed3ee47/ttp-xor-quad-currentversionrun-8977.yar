rule TTP_XOR_QUAD_CurrentVersionRun_8977 {
  strings:
    $key_8977 = { da 18 [2] fe 16 [2] d5 3a [2] fb 18 [2] ef 03 [2] e0 19 [2] fe 04 [2] fc 05 [2] e7 03 [2] fb 04 [2] e7 2b }

  condition:
    any of them
}