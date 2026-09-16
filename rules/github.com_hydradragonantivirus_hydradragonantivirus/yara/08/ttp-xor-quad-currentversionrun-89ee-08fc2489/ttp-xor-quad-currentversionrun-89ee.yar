rule TTP_XOR_QUAD_CurrentVersionRun_89ee {
  strings:
    $key_89ee = { da 81 [2] fe 8f [2] d5 a3 [2] fb 81 [2] ef 9a [2] e0 80 [2] fe 9d [2] fc 9c [2] e7 9a [2] fb 9d [2] e7 b2 }

  condition:
    any of them
}