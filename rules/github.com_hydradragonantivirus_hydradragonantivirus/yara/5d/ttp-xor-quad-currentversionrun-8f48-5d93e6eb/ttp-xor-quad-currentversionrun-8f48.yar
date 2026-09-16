rule TTP_XOR_QUAD_CurrentVersionRun_8f48 {
  strings:
    $key_8f48 = { dc 27 [2] f8 29 [2] d3 05 [2] fd 27 [2] e9 3c [2] e6 26 [2] f8 3b [2] fa 3a [2] e1 3c [2] fd 3b [2] e1 14 }

  condition:
    any of them
}