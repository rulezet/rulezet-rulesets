rule TTP_XOR_QUAD_CurrentVersionRun_89fe {
  strings:
    $key_89fe = { da 91 [2] fe 9f [2] d5 b3 [2] fb 91 [2] ef 8a [2] e0 90 [2] fe 8d [2] fc 8c [2] e7 8a [2] fb 8d [2] e7 a2 }

  condition:
    any of them
}