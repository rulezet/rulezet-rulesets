rule TTP_XOR_QUAD_CurrentVersionRun_8f4b {
  strings:
    $key_8f4b = { dc 24 [2] f8 2a [2] d3 06 [2] fd 24 [2] e9 3f [2] e6 25 [2] f8 38 [2] fa 39 [2] e1 3f [2] fd 38 [2] e1 17 }

  condition:
    any of them
}