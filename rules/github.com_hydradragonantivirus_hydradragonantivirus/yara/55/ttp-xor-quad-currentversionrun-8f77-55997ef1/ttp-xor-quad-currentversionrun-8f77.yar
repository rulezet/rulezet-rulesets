rule TTP_XOR_QUAD_CurrentVersionRun_8f77 {
  strings:
    $key_8f77 = { dc 18 [2] f8 16 [2] d3 3a [2] fd 18 [2] e9 03 [2] e6 19 [2] f8 04 [2] fa 05 [2] e1 03 [2] fd 04 [2] e1 2b }

  condition:
    any of them
}