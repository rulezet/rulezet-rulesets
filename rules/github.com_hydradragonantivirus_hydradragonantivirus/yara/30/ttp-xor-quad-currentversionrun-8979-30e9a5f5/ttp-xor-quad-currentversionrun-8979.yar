rule TTP_XOR_QUAD_CurrentVersionRun_8979 {
  strings:
    $key_8979 = { da 16 [2] fe 18 [2] d5 34 [2] fb 16 [2] ef 0d [2] e0 17 [2] fe 0a [2] fc 0b [2] e7 0d [2] fb 0a [2] e7 25 }

  condition:
    any of them
}