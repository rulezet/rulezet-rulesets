rule TTP_XOR_QUAD_CurrentVersionRun_8926 {
  strings:
    $key_8926 = { da 49 [2] fe 47 [2] d5 6b [2] fb 49 [2] ef 52 [2] e0 48 [2] fe 55 [2] fc 54 [2] e7 52 [2] fb 55 [2] e7 7a }

  condition:
    any of them
}