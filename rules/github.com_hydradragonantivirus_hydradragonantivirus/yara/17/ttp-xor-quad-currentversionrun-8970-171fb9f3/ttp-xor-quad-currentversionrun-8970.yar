rule TTP_XOR_QUAD_CurrentVersionRun_8970 {
  strings:
    $key_8970 = { da 1f [2] fe 11 [2] d5 3d [2] fb 1f [2] ef 04 [2] e0 1e [2] fe 03 [2] fc 02 [2] e7 04 [2] fb 03 [2] e7 2c }

  condition:
    any of them
}