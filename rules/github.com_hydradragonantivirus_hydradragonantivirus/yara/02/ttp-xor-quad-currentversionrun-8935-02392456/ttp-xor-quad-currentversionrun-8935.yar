rule TTP_XOR_QUAD_CurrentVersionRun_8935 {
  strings:
    $key_8935 = { da 5a [2] fe 54 [2] d5 78 [2] fb 5a [2] ef 41 [2] e0 5b [2] fe 46 [2] fc 47 [2] e7 41 [2] fb 46 [2] e7 69 }

  condition:
    any of them
}