rule TTP_XOR_QUAD_CurrentVersionRun_8953 {
  strings:
    $key_8953 = { da 3c [2] fe 32 [2] d5 1e [2] fb 3c [2] ef 27 [2] e0 3d [2] fe 20 [2] fc 21 [2] e7 27 [2] fb 20 [2] e7 0f }

  condition:
    any of them
}