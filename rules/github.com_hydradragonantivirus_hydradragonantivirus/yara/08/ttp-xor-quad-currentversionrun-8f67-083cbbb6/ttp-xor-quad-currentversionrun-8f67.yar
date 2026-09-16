rule TTP_XOR_QUAD_CurrentVersionRun_8f67 {
  strings:
    $key_8f67 = { dc 08 [2] f8 06 [2] d3 2a [2] fd 08 [2] e9 13 [2] e6 09 [2] f8 14 [2] fa 15 [2] e1 13 [2] fd 14 [2] e1 3b }

  condition:
    any of them
}