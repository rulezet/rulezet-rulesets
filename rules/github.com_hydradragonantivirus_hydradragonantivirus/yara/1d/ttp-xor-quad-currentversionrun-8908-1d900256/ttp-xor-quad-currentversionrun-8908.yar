rule TTP_XOR_QUAD_CurrentVersionRun_8908 {
  strings:
    $key_8908 = { da 67 [2] fe 69 [2] d5 45 [2] fb 67 [2] ef 7c [2] e0 66 [2] fe 7b [2] fc 7a [2] e7 7c [2] fb 7b [2] e7 54 }

  condition:
    any of them
}