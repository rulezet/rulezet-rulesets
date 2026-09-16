rule TTP_XOR_QUAD_CurrentVersionRun_8f6e {
  strings:
    $key_8f6e = { dc 01 [2] f8 0f [2] d3 23 [2] fd 01 [2] e9 1a [2] e6 00 [2] f8 1d [2] fa 1c [2] e1 1a [2] fd 1d [2] e1 32 }

  condition:
    any of them
}