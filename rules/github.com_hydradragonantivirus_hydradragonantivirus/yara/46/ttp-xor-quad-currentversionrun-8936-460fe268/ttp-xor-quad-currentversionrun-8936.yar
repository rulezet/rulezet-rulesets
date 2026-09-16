rule TTP_XOR_QUAD_CurrentVersionRun_8936 {
  strings:
    $key_8936 = { da 59 [2] fe 57 [2] d5 7b [2] fb 59 [2] ef 42 [2] e0 58 [2] fe 45 [2] fc 44 [2] e7 42 [2] fb 45 [2] e7 6a }

  condition:
    any of them
}