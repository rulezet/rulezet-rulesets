rule TTP_XOR_QUAD_CurrentVersionRun_8f6d {
  strings:
    $key_8f6d = { dc 02 [2] f8 0c [2] d3 20 [2] fd 02 [2] e9 19 [2] e6 03 [2] f8 1e [2] fa 1f [2] e1 19 [2] fd 1e [2] e1 31 }

  condition:
    any of them
}