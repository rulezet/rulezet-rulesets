rule TTP_XOR_QUAD_CurrentVersionRun_8fec {
  strings:
    $key_8fec = { dc 83 [2] f8 8d [2] d3 a1 [2] fd 83 [2] e9 98 [2] e6 82 [2] f8 9f [2] fa 9e [2] e1 98 [2] fd 9f [2] e1 b0 }

  condition:
    any of them
}