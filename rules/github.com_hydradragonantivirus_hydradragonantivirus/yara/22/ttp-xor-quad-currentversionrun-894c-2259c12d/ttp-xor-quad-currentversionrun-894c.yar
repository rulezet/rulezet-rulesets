rule TTP_XOR_QUAD_CurrentVersionRun_894c {
  strings:
    $key_894c = { da 23 [2] fe 2d [2] d5 01 [2] fb 23 [2] ef 38 [2] e0 22 [2] fe 3f [2] fc 3e [2] e7 38 [2] fb 3f [2] e7 10 }

  condition:
    any of them
}