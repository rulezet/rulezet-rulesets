rule TTP_XOR_QUAD_CurrentVersionRun_419e {
  strings:
    $key_419e = { 12 f1 [2] 36 ff [2] 1d d3 [2] 33 f1 [2] 27 ea [2] 28 f0 [2] 36 ed [2] 34 ec [2] 2f ea [2] 33 ed [2] 2f c2 }

  condition:
    any of them
}