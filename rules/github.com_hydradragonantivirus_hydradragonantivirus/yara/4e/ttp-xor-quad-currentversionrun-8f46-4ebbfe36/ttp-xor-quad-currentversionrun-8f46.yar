rule TTP_XOR_QUAD_CurrentVersionRun_8f46 {
  strings:
    $key_8f46 = { dc 29 [2] f8 27 [2] d3 0b [2] fd 29 [2] e9 32 [2] e6 28 [2] f8 35 [2] fa 34 [2] e1 32 [2] fd 35 [2] e1 1a }

  condition:
    any of them
}