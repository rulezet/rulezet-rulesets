rule TTP_XOR_QUAD_CurrentVersionRun_8950 {
  strings:
    $key_8950 = { da 3f [2] fe 31 [2] d5 1d [2] fb 3f [2] ef 24 [2] e0 3e [2] fe 23 [2] fc 22 [2] e7 24 [2] fb 23 [2] e7 0c }

  condition:
    any of them
}