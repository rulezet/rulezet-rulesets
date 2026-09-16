rule TTP_XOR_QUAD_CurrentVersionRun_8f76 {
  strings:
    $key_8f76 = { dc 19 [2] f8 17 [2] d3 3b [2] fd 19 [2] e9 02 [2] e6 18 [2] f8 05 [2] fa 04 [2] e1 02 [2] fd 05 [2] e1 2a }

  condition:
    any of them
}