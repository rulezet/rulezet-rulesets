rule TTP_XOR_QUAD_CurrentVersionRun_8f47 {
  strings:
    $key_8f47 = { dc 28 [2] f8 26 [2] d3 0a [2] fd 28 [2] e9 33 [2] e6 29 [2] f8 34 [2] fa 35 [2] e1 33 [2] fd 34 [2] e1 1b }

  condition:
    any of them
}