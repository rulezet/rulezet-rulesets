rule TTP_XOR_QUAD_CurrentVersionRun_8f9d {
  strings:
    $key_8f9d = { dc f2 [2] f8 fc [2] d3 d0 [2] fd f2 [2] e9 e9 [2] e6 f3 [2] f8 ee [2] fa ef [2] e1 e9 [2] fd ee [2] e1 c1 }

  condition:
    any of them
}