rule TTP_XOR_QUAD_CurrentVersionRun_8f49 {
  strings:
    $key_8f49 = { dc 26 [2] f8 28 [2] d3 04 [2] fd 26 [2] e9 3d [2] e6 27 [2] f8 3a [2] fa 3b [2] e1 3d [2] fd 3a [2] e1 15 }

  condition:
    any of them
}