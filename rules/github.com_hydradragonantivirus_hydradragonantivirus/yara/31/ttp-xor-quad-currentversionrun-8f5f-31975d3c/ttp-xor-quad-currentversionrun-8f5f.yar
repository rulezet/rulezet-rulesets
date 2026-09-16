rule TTP_XOR_QUAD_CurrentVersionRun_8f5f {
  strings:
    $key_8f5f = { dc 30 [2] f8 3e [2] d3 12 [2] fd 30 [2] e9 2b [2] e6 31 [2] f8 2c [2] fa 2d [2] e1 2b [2] fd 2c [2] e1 03 }

  condition:
    any of them
}