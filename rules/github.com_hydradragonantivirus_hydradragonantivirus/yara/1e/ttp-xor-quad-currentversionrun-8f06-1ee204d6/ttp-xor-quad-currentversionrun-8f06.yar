rule TTP_XOR_QUAD_CurrentVersionRun_8f06 {
  strings:
    $key_8f06 = { dc 69 [2] f8 67 [2] d3 4b [2] fd 69 [2] e9 72 [2] e6 68 [2] f8 75 [2] fa 74 [2] e1 72 [2] fd 75 [2] e1 5a }

  condition:
    any of them
}