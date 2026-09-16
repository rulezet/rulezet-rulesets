rule TTP_XOR_QUAD_CurrentVersionRun_8966 {
  strings:
    $key_8966 = { da 09 [2] fe 07 [2] d5 2b [2] fb 09 [2] ef 12 [2] e0 08 [2] fe 15 [2] fc 14 [2] e7 12 [2] fb 15 [2] e7 3a }

  condition:
    any of them
}