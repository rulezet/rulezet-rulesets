rule TTP_XOR_QUAD_CurrentVersionRun_8f5a {
  strings:
    $key_8f5a = { dc 35 [2] f8 3b [2] d3 17 [2] fd 35 [2] e9 2e [2] e6 34 [2] f8 29 [2] fa 28 [2] e1 2e [2] fd 29 [2] e1 06 }

  condition:
    any of them
}