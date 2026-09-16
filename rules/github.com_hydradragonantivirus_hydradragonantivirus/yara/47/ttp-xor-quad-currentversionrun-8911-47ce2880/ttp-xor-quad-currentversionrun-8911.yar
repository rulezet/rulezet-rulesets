rule TTP_XOR_QUAD_CurrentVersionRun_8911 {
  strings:
    $key_8911 = { da 7e [2] fe 70 [2] d5 5c [2] fb 7e [2] ef 65 [2] e0 7f [2] fe 62 [2] fc 63 [2] e7 65 [2] fb 62 [2] e7 4d }

  condition:
    any of them
}