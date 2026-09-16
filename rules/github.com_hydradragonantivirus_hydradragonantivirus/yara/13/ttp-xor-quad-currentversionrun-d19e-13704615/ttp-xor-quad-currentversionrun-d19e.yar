rule TTP_XOR_QUAD_CurrentVersionRun_d19e {
  strings:
    $key_d19e = { 82 f1 [2] a6 ff [2] 8d d3 [2] a3 f1 [2] b7 ea [2] b8 f0 [2] a6 ed [2] a4 ec [2] bf ea [2] a3 ed [2] bf c2 }

  condition:
    any of them
}