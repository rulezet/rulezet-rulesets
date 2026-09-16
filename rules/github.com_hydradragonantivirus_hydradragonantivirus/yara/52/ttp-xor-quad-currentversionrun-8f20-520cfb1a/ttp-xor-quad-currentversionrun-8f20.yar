rule TTP_XOR_QUAD_CurrentVersionRun_8f20 {
  strings:
    $key_8f20 = { dc 4f [2] f8 41 [2] d3 6d [2] fd 4f [2] e9 54 [2] e6 4e [2] f8 53 [2] fa 52 [2] e1 54 [2] fd 53 [2] e1 7c }

  condition:
    any of them
}