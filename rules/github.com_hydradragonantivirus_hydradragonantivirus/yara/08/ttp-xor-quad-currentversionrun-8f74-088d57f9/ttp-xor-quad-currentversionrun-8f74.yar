rule TTP_XOR_QUAD_CurrentVersionRun_8f74 {
  strings:
    $key_8f74 = { dc 1b [2] f8 15 [2] d3 39 [2] fd 1b [2] e9 00 [2] e6 1a [2] f8 07 [2] fa 06 [2] e1 00 [2] fd 07 [2] e1 28 }

  condition:
    any of them
}