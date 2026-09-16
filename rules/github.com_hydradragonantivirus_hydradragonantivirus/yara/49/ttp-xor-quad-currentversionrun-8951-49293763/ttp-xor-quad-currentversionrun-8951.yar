rule TTP_XOR_QUAD_CurrentVersionRun_8951 {
  strings:
    $key_8951 = { da 3e [2] fe 30 [2] d5 1c [2] fb 3e [2] ef 25 [2] e0 3f [2] fe 22 [2] fc 23 [2] e7 25 [2] fb 22 [2] e7 0d }

  condition:
    any of them
}