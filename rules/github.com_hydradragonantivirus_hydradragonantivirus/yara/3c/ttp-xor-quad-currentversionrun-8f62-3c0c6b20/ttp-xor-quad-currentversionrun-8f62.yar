rule TTP_XOR_QUAD_CurrentVersionRun_8f62 {
  strings:
    $key_8f62 = { dc 0d [2] f8 03 [2] d3 2f [2] fd 0d [2] e9 16 [2] e6 0c [2] f8 11 [2] fa 10 [2] e1 16 [2] fd 11 [2] e1 3e }

  condition:
    any of them
}