rule TTP_XOR_QUAD_CurrentVersionRun_8f03 {
  strings:
    $key_8f03 = { dc 6c [2] f8 62 [2] d3 4e [2] fd 6c [2] e9 77 [2] e6 6d [2] f8 70 [2] fa 71 [2] e1 77 [2] fd 70 [2] e1 5f }

  condition:
    any of them
}