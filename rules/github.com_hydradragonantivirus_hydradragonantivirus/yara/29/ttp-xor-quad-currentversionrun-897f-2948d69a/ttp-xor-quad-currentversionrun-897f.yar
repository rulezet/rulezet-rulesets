rule TTP_XOR_QUAD_CurrentVersionRun_897f {
  strings:
    $key_897f = { da 10 [2] fe 1e [2] d5 32 [2] fb 10 [2] ef 0b [2] e0 11 [2] fe 0c [2] fc 0d [2] e7 0b [2] fb 0c [2] e7 23 }

  condition:
    any of them
}