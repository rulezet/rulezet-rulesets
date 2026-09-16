rule TTP_XOR_QUAD_CurrentVersionRun_8939 {
  strings:
    $key_8939 = { da 56 [2] fe 58 [2] d5 74 [2] fb 56 [2] ef 4d [2] e0 57 [2] fe 4a [2] fc 4b [2] e7 4d [2] fb 4a [2] e7 65 }

  condition:
    any of them
}