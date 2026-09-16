rule TTP_XOR_QUAD_CurrentVersionRun_8fea {
  strings:
    $key_8fea = { dc 85 [2] f8 8b [2] d3 a7 [2] fd 85 [2] e9 9e [2] e6 84 [2] f8 99 [2] fa 98 [2] e1 9e [2] fd 99 [2] e1 b6 }

  condition:
    any of them
}