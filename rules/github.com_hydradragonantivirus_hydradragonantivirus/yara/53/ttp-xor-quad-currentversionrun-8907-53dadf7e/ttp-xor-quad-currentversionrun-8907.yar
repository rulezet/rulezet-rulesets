rule TTP_XOR_QUAD_CurrentVersionRun_8907 {
  strings:
    $key_8907 = { da 68 [2] fe 66 [2] d5 4a [2] fb 68 [2] ef 73 [2] e0 69 [2] fe 74 [2] fc 75 [2] e7 73 [2] fb 74 [2] e7 5b }

  condition:
    any of them
}