rule TTP_XOR_QUAD_CurrentVersionRun_8fa8 {
  strings:
    $key_8fa8 = { dc c7 [2] f8 c9 [2] d3 e5 [2] fd c7 [2] e9 dc [2] e6 c6 [2] f8 db [2] fa da [2] e1 dc [2] fd db [2] e1 f4 }

  condition:
    any of them
}