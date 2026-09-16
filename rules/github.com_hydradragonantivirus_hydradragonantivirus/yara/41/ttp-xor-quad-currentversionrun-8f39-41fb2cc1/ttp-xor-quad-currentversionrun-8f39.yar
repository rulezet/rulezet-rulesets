rule TTP_XOR_QUAD_CurrentVersionRun_8f39 {
  strings:
    $key_8f39 = { dc 56 [2] f8 58 [2] d3 74 [2] fd 56 [2] e9 4d [2] e6 57 [2] f8 4a [2] fa 4b [2] e1 4d [2] fd 4a [2] e1 65 }

  condition:
    any of them
}