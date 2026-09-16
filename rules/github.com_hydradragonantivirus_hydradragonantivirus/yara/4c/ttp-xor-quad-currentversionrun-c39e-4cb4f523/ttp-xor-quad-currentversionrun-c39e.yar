rule TTP_XOR_QUAD_CurrentVersionRun_c39e {
  strings:
    $key_c39e = { 90 f1 [2] b4 ff [2] 9f d3 [2] b1 f1 [2] a5 ea [2] aa f0 [2] b4 ed [2] b6 ec [2] ad ea [2] b1 ed [2] ad c2 }

  condition:
    any of them
}