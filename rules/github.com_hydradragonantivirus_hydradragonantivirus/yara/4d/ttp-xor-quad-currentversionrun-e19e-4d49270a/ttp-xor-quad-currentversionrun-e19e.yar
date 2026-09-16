rule TTP_XOR_QUAD_CurrentVersionRun_e19e {
  strings:
    $key_e19e = { b2 f1 [2] 96 ff [2] bd d3 [2] 93 f1 [2] 87 ea [2] 88 f0 [2] 96 ed [2] 94 ec [2] 8f ea [2] 93 ed [2] 8f c2 }

  condition:
    any of them
}