rule TTP_XOR_QUAD_CurrentVersionRun_8f8e {
  strings:
    $key_8f8e = { dc e1 [2] f8 ef [2] d3 c3 [2] fd e1 [2] e9 fa [2] e6 e0 [2] f8 fd [2] fa fc [2] e1 fa [2] fd fd [2] e1 d2 }

  condition:
    any of them
}