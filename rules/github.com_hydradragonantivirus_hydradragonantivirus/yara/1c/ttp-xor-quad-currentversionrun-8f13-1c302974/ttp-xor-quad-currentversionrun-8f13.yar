rule TTP_XOR_QUAD_CurrentVersionRun_8f13 {
  strings:
    $key_8f13 = { dc 7c [2] f8 72 [2] d3 5e [2] fd 7c [2] e9 67 [2] e6 7d [2] f8 60 [2] fa 61 [2] e1 67 [2] fd 60 [2] e1 4f }

  condition:
    any of them
}