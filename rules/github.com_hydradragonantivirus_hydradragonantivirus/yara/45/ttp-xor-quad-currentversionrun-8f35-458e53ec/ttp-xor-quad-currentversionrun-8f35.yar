rule TTP_XOR_QUAD_CurrentVersionRun_8f35 {
  strings:
    $key_8f35 = { dc 5a [2] f8 54 [2] d3 78 [2] fd 5a [2] e9 41 [2] e6 5b [2] f8 46 [2] fa 47 [2] e1 41 [2] fd 46 [2] e1 69 }

  condition:
    any of them
}