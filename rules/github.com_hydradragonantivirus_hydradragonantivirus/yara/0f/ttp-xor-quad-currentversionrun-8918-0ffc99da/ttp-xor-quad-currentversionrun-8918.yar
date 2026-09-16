rule TTP_XOR_QUAD_CurrentVersionRun_8918 {
  strings:
    $key_8918 = { da 77 [2] fe 79 [2] d5 55 [2] fb 77 [2] ef 6c [2] e0 76 [2] fe 6b [2] fc 6a [2] e7 6c [2] fb 6b [2] e7 44 }

  condition:
    any of them
}