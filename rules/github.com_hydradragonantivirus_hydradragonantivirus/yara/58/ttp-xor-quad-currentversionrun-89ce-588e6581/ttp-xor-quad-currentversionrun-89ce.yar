rule TTP_XOR_QUAD_CurrentVersionRun_89ce {
  strings:
    $key_89ce = { da a1 [2] fe af [2] d5 83 [2] fb a1 [2] ef ba [2] e0 a0 [2] fe bd [2] fc bc [2] e7 ba [2] fb bd [2] e7 92 }

  condition:
    any of them
}