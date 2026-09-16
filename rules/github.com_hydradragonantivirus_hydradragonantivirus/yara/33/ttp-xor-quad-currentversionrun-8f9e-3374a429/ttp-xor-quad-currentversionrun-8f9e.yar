rule TTP_XOR_QUAD_CurrentVersionRun_8f9e {
  strings:
    $key_8f9e = { dc f1 [2] f8 ff [2] d3 d3 [2] fd f1 [2] e9 ea [2] e6 f0 [2] f8 ed [2] fa ec [2] e1 ea [2] fd ed [2] e1 c2 }

  condition:
    any of them
}