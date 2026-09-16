rule TTP_XOR_QUAD_CurrentVersionRun_8f66 {
  strings:
    $key_8f66 = { dc 09 [2] f8 07 [2] d3 2b [2] fd 09 [2] e9 12 [2] e6 08 [2] f8 15 [2] fa 14 [2] e1 12 [2] fd 15 [2] e1 3a }

  condition:
    any of them
}