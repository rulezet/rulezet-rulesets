rule TTP_XOR_QUAD_CurrentVersionRun_896c {
  strings:
    $key_896c = { da 03 [2] fe 0d [2] d5 21 [2] fb 03 [2] ef 18 [2] e0 02 [2] fe 1f [2] fc 1e [2] e7 18 [2] fb 1f [2] e7 30 }

  condition:
    any of them
}