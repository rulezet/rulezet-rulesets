rule TTP_XOR_QUAD_CurrentVersionRun_8cdd {
  strings:
    $key_8cdd = { df b2 [2] fb bc [2] d0 90 [2] fe b2 [2] ea a9 [2] e5 b3 [2] fb ae [2] f9 af [2] e2 a9 [2] fe ae [2] e2 81 }

  condition:
    any of them
}