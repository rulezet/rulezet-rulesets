rule TTP_XOR_QUAD_CurrentVersionRun_8f43 {
  strings:
    $key_8f43 = { dc 2c [2] f8 22 [2] d3 0e [2] fd 2c [2] e9 37 [2] e6 2d [2] f8 30 [2] fa 31 [2] e1 37 [2] fd 30 [2] e1 1f }

  condition:
    any of them
}