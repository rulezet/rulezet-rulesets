rule TTP_XOR_QUAD_CurrentVersionRun_8f68 {
  strings:
    $key_8f68 = { dc 07 [2] f8 09 [2] d3 25 [2] fd 07 [2] e9 1c [2] e6 06 [2] f8 1b [2] fa 1a [2] e1 1c [2] fd 1b [2] e1 34 }

  condition:
    any of them
}