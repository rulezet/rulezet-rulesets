rule TTP_XOR_QUAD_CurrentVersionRun_89fb {
  strings:
    $key_89fb = { da 94 [2] fe 9a [2] d5 b6 [2] fb 94 [2] ef 8f [2] e0 95 [2] fe 88 [2] fc 89 [2] e7 8f [2] fb 88 [2] e7 a7 }

  condition:
    any of them
}