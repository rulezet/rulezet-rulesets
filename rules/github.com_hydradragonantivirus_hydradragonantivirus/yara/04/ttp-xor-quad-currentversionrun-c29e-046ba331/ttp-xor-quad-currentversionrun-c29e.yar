rule TTP_XOR_QUAD_CurrentVersionRun_c29e {
  strings:
    $key_c29e = { 91 f1 [2] b5 ff [2] 9e d3 [2] b0 f1 [2] a4 ea [2] ab f0 [2] b5 ed [2] b7 ec [2] ac ea [2] b0 ed [2] ac c2 }

  condition:
    any of them
}