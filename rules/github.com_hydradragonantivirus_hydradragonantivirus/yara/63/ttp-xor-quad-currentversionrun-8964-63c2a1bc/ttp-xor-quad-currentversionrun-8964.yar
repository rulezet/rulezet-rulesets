rule TTP_XOR_QUAD_CurrentVersionRun_8964 {
  strings:
    $key_8964 = { da 0b [2] fe 05 [2] d5 29 [2] fb 0b [2] ef 10 [2] e0 0a [2] fe 17 [2] fc 16 [2] e7 10 [2] fb 17 [2] e7 38 }

  condition:
    any of them
}