rule TTP_XOR_QUAD_CurrentVersionRun_95b1 {
  strings:
    $key_95b1 = { c6 de [2] e2 d0 [2] c9 fc [2] e7 de [2] f3 c5 [2] fc df [2] e2 c2 [2] e0 c3 [2] fb c5 [2] e7 c2 [2] fb ed }

  condition:
    any of them
}