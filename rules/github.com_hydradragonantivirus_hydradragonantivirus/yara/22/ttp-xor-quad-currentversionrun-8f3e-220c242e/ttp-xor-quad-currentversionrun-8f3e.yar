rule TTP_XOR_QUAD_CurrentVersionRun_8f3e {
  strings:
    $key_8f3e = { dc 51 [2] f8 5f [2] d3 73 [2] fd 51 [2] e9 4a [2] e6 50 [2] f8 4d [2] fa 4c [2] e1 4a [2] fd 4d [2] e1 62 }

  condition:
    any of them
}