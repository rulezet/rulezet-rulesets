rule TTP_XOR_QUAD_CurrentVersionRun_8f16 {
  strings:
    $key_8f16 = { dc 79 [2] f8 77 [2] d3 5b [2] fd 79 [2] e9 62 [2] e6 78 [2] f8 65 [2] fa 64 [2] e1 62 [2] fd 65 [2] e1 4a }

  condition:
    any of them
}