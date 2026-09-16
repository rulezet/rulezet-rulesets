rule TTP_XOR_QUAD_CurrentVersionRun_939e {
  strings:
    $key_939e = { c0 f1 [2] e4 ff [2] cf d3 [2] e1 f1 [2] f5 ea [2] fa f0 [2] e4 ed [2] e6 ec [2] fd ea [2] e1 ed [2] fd c2 }

  condition:
    any of them
}