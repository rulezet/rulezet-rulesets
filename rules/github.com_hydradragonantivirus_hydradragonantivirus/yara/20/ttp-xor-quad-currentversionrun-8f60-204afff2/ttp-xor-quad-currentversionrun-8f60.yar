rule TTP_XOR_QUAD_CurrentVersionRun_8f60 {
  strings:
    $key_8f60 = { dc 0f [2] f8 01 [2] d3 2d [2] fd 0f [2] e9 14 [2] e6 0e [2] f8 13 [2] fa 12 [2] e1 14 [2] fd 13 [2] e1 3c }

  condition:
    any of them
}