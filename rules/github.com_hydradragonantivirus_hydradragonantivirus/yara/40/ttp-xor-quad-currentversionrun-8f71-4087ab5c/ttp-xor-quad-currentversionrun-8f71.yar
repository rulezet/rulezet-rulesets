rule TTP_XOR_QUAD_CurrentVersionRun_8f71 {
  strings:
    $key_8f71 = { dc 1e [2] f8 10 [2] d3 3c [2] fd 1e [2] e9 05 [2] e6 1f [2] f8 02 [2] fa 03 [2] e1 05 [2] fd 02 [2] e1 2d }

  condition:
    any of them
}