rule TTP_XOR_QUAD_CurrentVersionRun_8f40 {
  strings:
    $key_8f40 = { dc 2f [2] f8 21 [2] d3 0d [2] fd 2f [2] e9 34 [2] e6 2e [2] f8 33 [2] fa 32 [2] e1 34 [2] fd 33 [2] e1 1c }

  condition:
    any of them
}