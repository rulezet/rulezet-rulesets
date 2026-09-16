rule TTP_XOR_QUAD_CurrentVersionRun_839e {
  strings:
    $key_839e = { d0 f1 [2] f4 ff [2] df d3 [2] f1 f1 [2] e5 ea [2] ea f0 [2] f4 ed [2] f6 ec [2] ed ea [2] f1 ed [2] ed c2 }

  condition:
    any of them
}