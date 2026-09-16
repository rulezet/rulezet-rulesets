rule TTP_XOR_QUAD_CurrentVersionRun_8edc {
  strings:
    $key_8edc = { dd b3 [2] f9 bd [2] d2 91 [2] fc b3 [2] e8 a8 [2] e7 b2 [2] f9 af [2] fb ae [2] e0 a8 [2] fc af [2] e0 80 }

  condition:
    any of them
}