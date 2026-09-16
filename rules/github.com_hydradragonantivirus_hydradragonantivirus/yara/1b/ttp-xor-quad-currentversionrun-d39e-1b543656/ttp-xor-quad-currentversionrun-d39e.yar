rule TTP_XOR_QUAD_CurrentVersionRun_d39e {
  strings:
    $key_d39e = { 80 f1 [2] a4 ff [2] 8f d3 [2] a1 f1 [2] b5 ea [2] ba f0 [2] a4 ed [2] a6 ec [2] bd ea [2] a1 ed [2] bd c2 }

  condition:
    any of them
}