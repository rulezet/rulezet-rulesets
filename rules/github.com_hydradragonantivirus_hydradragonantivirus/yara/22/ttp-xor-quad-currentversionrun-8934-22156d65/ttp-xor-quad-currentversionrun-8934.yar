rule TTP_XOR_QUAD_CurrentVersionRun_8934 {
  strings:
    $key_8934 = { da 5b [2] fe 55 [2] d5 79 [2] fb 5b [2] ef 40 [2] e0 5a [2] fe 47 [2] fc 46 [2] e7 40 [2] fb 47 [2] e7 68 }

  condition:
    any of them
}