rule TTP_XOR_QUAD_CurrentVersionRun_92a6 {
  strings:
    $key_92a6 = { c1 c9 [2] e5 c7 [2] ce eb [2] e0 c9 [2] f4 d2 [2] fb c8 [2] e5 d5 [2] e7 d4 [2] fc d2 [2] e0 d5 [2] fc fa }

  condition:
    any of them
}