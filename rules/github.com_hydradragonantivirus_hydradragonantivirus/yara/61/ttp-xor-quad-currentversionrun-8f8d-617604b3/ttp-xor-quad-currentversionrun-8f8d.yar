rule TTP_XOR_QUAD_CurrentVersionRun_8f8d {
  strings:
    $key_8f8d = { dc e2 [2] f8 ec [2] d3 c0 [2] fd e2 [2] e9 f9 [2] e6 e3 [2] f8 fe [2] fa ff [2] e1 f9 [2] fd fe [2] e1 d1 }

  condition:
    any of them
}