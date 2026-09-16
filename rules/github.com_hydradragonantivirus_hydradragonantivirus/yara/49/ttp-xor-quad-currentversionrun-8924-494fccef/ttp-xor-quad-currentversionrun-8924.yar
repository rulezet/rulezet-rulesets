rule TTP_XOR_QUAD_CurrentVersionRun_8924 {
  strings:
    $key_8924 = { da 4b [2] fe 45 [2] d5 69 [2] fb 4b [2] ef 50 [2] e0 4a [2] fe 57 [2] fc 56 [2] e7 50 [2] fb 57 [2] e7 78 }

  condition:
    any of them
}