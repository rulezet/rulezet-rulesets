rule TTP_XOR_QUAD_CurrentVersionRun_8913 {
  strings:
    $key_8913 = { da 7c [2] fe 72 [2] d5 5e [2] fb 7c [2] ef 67 [2] e0 7d [2] fe 60 [2] fc 61 [2] e7 67 [2] fb 60 [2] e7 4f }

  condition:
    any of them
}