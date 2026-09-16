rule TTP_XOR_QUAD_CurrentVersionRun_8945 {
  strings:
    $key_8945 = { da 2a [2] fe 24 [2] d5 08 [2] fb 2a [2] ef 31 [2] e0 2b [2] fe 36 [2] fc 37 [2] e7 31 [2] fb 36 [2] e7 19 }

  condition:
    any of them
}