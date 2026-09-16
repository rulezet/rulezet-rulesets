rule TTP_XOR_QUAD_CurrentVersionRun_8f96 {
  strings:
    $key_8f96 = { dc f9 [2] f8 f7 [2] d3 db [2] fd f9 [2] e9 e2 [2] e6 f8 [2] f8 e5 [2] fa e4 [2] e1 e2 [2] fd e5 [2] e1 ca }

  condition:
    any of them
}