rule TTP_XOR_QUAD_CurrentVersionRun_8f4d {
  strings:
    $key_8f4d = { dc 22 [2] f8 2c [2] d3 00 [2] fd 22 [2] e9 39 [2] e6 23 [2] f8 3e [2] fa 3f [2] e1 39 [2] fd 3e [2] e1 11 }

  condition:
    any of them
}