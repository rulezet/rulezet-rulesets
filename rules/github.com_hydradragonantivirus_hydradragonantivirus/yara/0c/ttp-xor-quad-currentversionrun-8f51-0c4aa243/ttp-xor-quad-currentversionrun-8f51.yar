rule TTP_XOR_QUAD_CurrentVersionRun_8f51 {
  strings:
    $key_8f51 = { dc 3e [2] f8 30 [2] d3 1c [2] fd 3e [2] e9 25 [2] e6 3f [2] f8 22 [2] fa 23 [2] e1 25 [2] fd 22 [2] e1 0d }

  condition:
    any of them
}