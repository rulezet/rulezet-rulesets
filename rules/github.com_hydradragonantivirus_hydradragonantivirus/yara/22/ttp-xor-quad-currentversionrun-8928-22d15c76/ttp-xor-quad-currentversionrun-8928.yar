rule TTP_XOR_QUAD_CurrentVersionRun_8928 {
  strings:
    $key_8928 = { da 47 [2] fe 49 [2] d5 65 [2] fb 47 [2] ef 5c [2] e0 46 [2] fe 5b [2] fc 5a [2] e7 5c [2] fb 5b [2] e7 74 }

  condition:
    any of them
}