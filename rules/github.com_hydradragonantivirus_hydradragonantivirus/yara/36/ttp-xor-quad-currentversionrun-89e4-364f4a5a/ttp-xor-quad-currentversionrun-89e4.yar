rule TTP_XOR_QUAD_CurrentVersionRun_89e4 {
  strings:
    $key_89e4 = { da 8b [2] fe 85 [2] d5 a9 [2] fb 8b [2] ef 90 [2] e0 8a [2] fe 97 [2] fc 96 [2] e7 90 [2] fb 97 [2] e7 b8 }

  condition:
    any of them
}