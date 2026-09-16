rule TTP_XOR_QUAD_CurrentVersionRun_8f7d {
  strings:
    $key_8f7d = { dc 12 [2] f8 1c [2] d3 30 [2] fd 12 [2] e9 09 [2] e6 13 [2] f8 0e [2] fa 0f [2] e1 09 [2] fd 0e [2] e1 21 }

  condition:
    any of them
}