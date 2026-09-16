rule TTP_XOR_QUAD_CurrentVersionRun_89e8 {
  strings:
    $key_89e8 = { da 87 [2] fe 89 [2] d5 a5 [2] fb 87 [2] ef 9c [2] e0 86 [2] fe 9b [2] fc 9a [2] e7 9c [2] fb 9b [2] e7 b4 }

  condition:
    any of them
}