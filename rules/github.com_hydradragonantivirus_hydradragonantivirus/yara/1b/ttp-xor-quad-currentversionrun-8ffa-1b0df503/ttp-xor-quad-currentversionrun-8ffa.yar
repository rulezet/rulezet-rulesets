rule TTP_XOR_QUAD_CurrentVersionRun_8ffa {
  strings:
    $key_8ffa = { dc 95 [2] f8 9b [2] d3 b7 [2] fd 95 [2] e9 8e [2] e6 94 [2] f8 89 [2] fa 88 [2] e1 8e [2] fd 89 [2] e1 a6 }

  condition:
    any of them
}