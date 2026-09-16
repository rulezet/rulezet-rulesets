rule TTP_XOR_QUAD_CurrentVersionRun_8fa6 {
  strings:
    $key_8fa6 = { dc c9 [2] f8 c7 [2] d3 eb [2] fd c9 [2] e9 d2 [2] e6 c8 [2] f8 d5 [2] fa d4 [2] e1 d2 [2] fd d5 [2] e1 fa }

  condition:
    any of them
}