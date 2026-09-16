rule TTP_XOR_QUAD_CurrentVersionRun_8f59 {
  strings:
    $key_8f59 = { dc 36 [2] f8 38 [2] d3 14 [2] fd 36 [2] e9 2d [2] e6 37 [2] f8 2a [2] fa 2b [2] e1 2d [2] fd 2a [2] e1 05 }

  condition:
    any of them
}