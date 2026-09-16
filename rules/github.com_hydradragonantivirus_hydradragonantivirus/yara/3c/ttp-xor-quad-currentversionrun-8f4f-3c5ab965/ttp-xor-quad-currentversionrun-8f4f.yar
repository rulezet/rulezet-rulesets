rule TTP_XOR_QUAD_CurrentVersionRun_8f4f {
  strings:
    $key_8f4f = { dc 20 [2] f8 2e [2] d3 02 [2] fd 20 [2] e9 3b [2] e6 21 [2] f8 3c [2] fa 3d [2] e1 3b [2] fd 3c [2] e1 13 }

  condition:
    any of them
}