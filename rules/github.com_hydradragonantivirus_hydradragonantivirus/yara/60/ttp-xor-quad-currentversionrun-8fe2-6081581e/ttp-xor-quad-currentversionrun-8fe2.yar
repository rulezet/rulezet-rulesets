rule TTP_XOR_QUAD_CurrentVersionRun_8fe2 {
  strings:
    $key_8fe2 = { dc 8d [2] f8 83 [2] d3 af [2] fd 8d [2] e9 96 [2] e6 8c [2] f8 91 [2] fa 90 [2] e1 96 [2] fd 91 [2] e1 be }

  condition:
    any of them
}