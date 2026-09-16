rule TTP_XOR_QUAD_CurrentVersionRun_8f91 {
  strings:
    $key_8f91 = { dc fe [2] f8 f0 [2] d3 dc [2] fd fe [2] e9 e5 [2] e6 ff [2] f8 e2 [2] fa e3 [2] e1 e5 [2] fd e2 [2] e1 cd }

  condition:
    any of them
}