rule TTP_XOR_QUAD_CurrentVersionRun_8f56 {
  strings:
    $key_8f56 = { dc 39 [2] f8 37 [2] d3 1b [2] fd 39 [2] e9 22 [2] e6 38 [2] f8 25 [2] fa 24 [2] e1 22 [2] fd 25 [2] e1 0a }

  condition:
    any of them
}