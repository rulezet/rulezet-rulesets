rule TTP_XOR_QUAD_CurrentVersionRun_8f2a {
  strings:
    $key_8f2a = { dc 45 [2] f8 4b [2] d3 67 [2] fd 45 [2] e9 5e [2] e6 44 [2] f8 59 [2] fa 58 [2] e1 5e [2] fd 59 [2] e1 76 }

  condition:
    any of them
}