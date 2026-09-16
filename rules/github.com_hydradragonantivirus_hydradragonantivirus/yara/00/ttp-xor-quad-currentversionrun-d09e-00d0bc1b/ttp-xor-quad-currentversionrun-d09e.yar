rule TTP_XOR_QUAD_CurrentVersionRun_d09e {
  strings:
    $key_d09e = { 83 f1 [2] a7 ff [2] 8c d3 [2] a2 f1 [2] b6 ea [2] b9 f0 [2] a7 ed [2] a5 ec [2] be ea [2] a2 ed [2] be c2 }

  condition:
    any of them
}