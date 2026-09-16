rule TTP_XOR_QUAD_CurrentVersionRun_679e {
  strings:
    $key_679e = { 34 f1 [2] 10 ff [2] 3b d3 [2] 15 f1 [2] 01 ea [2] 0e f0 [2] 10 ed [2] 12 ec [2] 09 ea [2] 15 ed [2] 09 c2 }

  condition:
    any of them
}