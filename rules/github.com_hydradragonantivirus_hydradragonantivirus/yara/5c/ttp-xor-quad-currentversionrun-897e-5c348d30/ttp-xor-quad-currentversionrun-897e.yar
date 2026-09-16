rule TTP_XOR_QUAD_CurrentVersionRun_897e {
  strings:
    $key_897e = { da 11 [2] fe 1f [2] d5 33 [2] fb 11 [2] ef 0a [2] e0 10 [2] fe 0d [2] fc 0c [2] e7 0a [2] fb 0d [2] e7 22 }

  condition:
    any of them
}