rule TTP_XOR_QUAD_CurrentVersionRun_8f75 {
  strings:
    $key_8f75 = { dc 1a [2] f8 14 [2] d3 38 [2] fd 1a [2] e9 01 [2] e6 1b [2] f8 06 [2] fa 07 [2] e1 01 [2] fd 06 [2] e1 29 }

  condition:
    any of them
}