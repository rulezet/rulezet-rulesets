rule TTP_XOR_QUAD_CurrentVersionRun_b58e {
  strings:
    $key_b58e = { e6 e1 [2] c2 ef [2] e9 c3 [2] c7 e1 [2] d3 fa [2] dc e0 [2] c2 fd [2] c0 fc [2] db fa [2] c7 fd [2] db d2 }

  condition:
    any of them
}