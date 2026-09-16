rule TTP_XOR_QUAD_CurrentVersionRun_8f4c {
  strings:
    $key_8f4c = { dc 23 [2] f8 2d [2] d3 01 [2] fd 23 [2] e9 38 [2] e6 22 [2] f8 3f [2] fa 3e [2] e1 38 [2] fd 3f [2] e1 10 }

  condition:
    any of them
}