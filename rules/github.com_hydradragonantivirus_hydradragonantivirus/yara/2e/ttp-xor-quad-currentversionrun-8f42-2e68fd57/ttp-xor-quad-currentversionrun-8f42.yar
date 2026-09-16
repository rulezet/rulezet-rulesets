rule TTP_XOR_QUAD_CurrentVersionRun_8f42 {
  strings:
    $key_8f42 = { dc 2d [2] f8 23 [2] d3 0f [2] fd 2d [2] e9 36 [2] e6 2c [2] f8 31 [2] fa 30 [2] e1 36 [2] fd 31 [2] e1 1e }

  condition:
    any of them
}