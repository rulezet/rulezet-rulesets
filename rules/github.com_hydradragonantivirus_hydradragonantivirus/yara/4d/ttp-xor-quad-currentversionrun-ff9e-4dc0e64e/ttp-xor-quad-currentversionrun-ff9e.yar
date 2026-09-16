rule TTP_XOR_QUAD_CurrentVersionRun_ff9e {
  strings:
    $key_ff9e = { ac f1 [2] 88 ff [2] a3 d3 [2] 8d f1 [2] 99 ea [2] 96 f0 [2] 88 ed [2] 8a ec [2] 91 ea [2] 8d ed [2] 91 c2 }

  condition:
    any of them
}