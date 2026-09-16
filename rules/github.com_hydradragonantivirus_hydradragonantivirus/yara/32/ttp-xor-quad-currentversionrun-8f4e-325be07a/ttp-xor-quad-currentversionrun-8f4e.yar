rule TTP_XOR_QUAD_CurrentVersionRun_8f4e {
  strings:
    $key_8f4e = { dc 21 [2] f8 2f [2] d3 03 [2] fd 21 [2] e9 3a [2] e6 20 [2] f8 3d [2] fa 3c [2] e1 3a [2] fd 3d [2] e1 12 }

  condition:
    any of them
}