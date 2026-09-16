rule TTP_XOR_QUAD_CurrentVersionRun_8ff1 {
  strings:
    $key_8ff1 = { dc 9e [2] f8 90 [2] d3 bc [2] fd 9e [2] e9 85 [2] e6 9f [2] f8 82 [2] fa 83 [2] e1 85 [2] fd 82 [2] e1 ad }

  condition:
    any of them
}