rule TTP_XOR_QUAD_CurrentVersionRun_8f61 {
  strings:
    $key_8f61 = { dc 0e [2] f8 00 [2] d3 2c [2] fd 0e [2] e9 15 [2] e6 0f [2] f8 12 [2] fa 13 [2] e1 15 [2] fd 12 [2] e1 3d }

  condition:
    any of them
}