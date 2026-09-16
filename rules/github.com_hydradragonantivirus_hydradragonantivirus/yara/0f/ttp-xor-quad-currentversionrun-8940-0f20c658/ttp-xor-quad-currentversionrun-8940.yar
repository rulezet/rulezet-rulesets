rule TTP_XOR_QUAD_CurrentVersionRun_8940 {
  strings:
    $key_8940 = { da 2f [2] fe 21 [2] d5 0d [2] fb 2f [2] ef 34 [2] e0 2e [2] fe 33 [2] fc 32 [2] e7 34 [2] fb 33 [2] e7 1c }

  condition:
    any of them
}