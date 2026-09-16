rule TTP_XOR_QUAD_CurrentVersionRun_8f09 {
  strings:
    $key_8f09 = { dc 66 [2] f8 68 [2] d3 44 [2] fd 66 [2] e9 7d [2] e6 67 [2] f8 7a [2] fa 7b [2] e1 7d [2] fd 7a [2] e1 55 }

  condition:
    any of them
}