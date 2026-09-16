rule TTP_XOR_QUAD_CurrentVersionRun_8942 {
  strings:
    $key_8942 = { da 2d [2] fe 23 [2] d5 0f [2] fb 2d [2] ef 36 [2] e0 2c [2] fe 31 [2] fc 30 [2] e7 36 [2] fb 31 [2] e7 1e }

  condition:
    any of them
}