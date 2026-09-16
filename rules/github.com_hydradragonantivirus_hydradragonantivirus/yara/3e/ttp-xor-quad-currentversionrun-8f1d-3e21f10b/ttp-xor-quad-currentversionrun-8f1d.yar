rule TTP_XOR_QUAD_CurrentVersionRun_8f1d {
  strings:
    $key_8f1d = { dc 72 [2] f8 7c [2] d3 50 [2] fd 72 [2] e9 69 [2] e6 73 [2] f8 6e [2] fa 6f [2] e1 69 [2] fd 6e [2] e1 41 }

  condition:
    any of them
}