rule TTP_XOR_QUAD_CurrentVersionRun_8927 {
  strings:
    $key_8927 = { da 48 [2] fe 46 [2] d5 6a [2] fb 48 [2] ef 53 [2] e0 49 [2] fe 54 [2] fc 55 [2] e7 53 [2] fb 54 [2] e7 7b }

  condition:
    any of them
}