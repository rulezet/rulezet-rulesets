rule TTP_XOR_QUAD_CurrentVersionRun_8f57 {
  strings:
    $key_8f57 = { dc 38 [2] f8 36 [2] d3 1a [2] fd 38 [2] e9 23 [2] e6 39 [2] f8 24 [2] fa 25 [2] e1 23 [2] fd 24 [2] e1 0b }

  condition:
    any of them
}