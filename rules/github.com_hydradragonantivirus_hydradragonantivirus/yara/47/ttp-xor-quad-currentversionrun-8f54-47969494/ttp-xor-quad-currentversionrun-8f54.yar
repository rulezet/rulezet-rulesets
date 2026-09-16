rule TTP_XOR_QUAD_CurrentVersionRun_8f54 {
  strings:
    $key_8f54 = { dc 3b [2] f8 35 [2] d3 19 [2] fd 3b [2] e9 20 [2] e6 3a [2] f8 27 [2] fa 26 [2] e1 20 [2] fd 27 [2] e1 08 }

  condition:
    any of them
}