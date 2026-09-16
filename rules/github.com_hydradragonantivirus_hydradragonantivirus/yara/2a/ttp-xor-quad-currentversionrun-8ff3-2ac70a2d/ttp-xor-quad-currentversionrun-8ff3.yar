rule TTP_XOR_QUAD_CurrentVersionRun_8ff3 {
  strings:
    $key_8ff3 = { dc 9c [2] f8 92 [2] d3 be [2] fd 9c [2] e9 87 [2] e6 9d [2] f8 80 [2] fa 81 [2] e1 87 [2] fd 80 [2] e1 af }

  condition:
    any of them
}