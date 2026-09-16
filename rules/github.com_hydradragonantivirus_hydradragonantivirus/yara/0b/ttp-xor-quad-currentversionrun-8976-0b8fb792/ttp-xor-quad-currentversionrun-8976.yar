rule TTP_XOR_QUAD_CurrentVersionRun_8976 {
  strings:
    $key_8976 = { da 19 [2] fe 17 [2] d5 3b [2] fb 19 [2] ef 02 [2] e0 18 [2] fe 05 [2] fc 04 [2] e7 02 [2] fb 05 [2] e7 2a }

  condition:
    any of them
}