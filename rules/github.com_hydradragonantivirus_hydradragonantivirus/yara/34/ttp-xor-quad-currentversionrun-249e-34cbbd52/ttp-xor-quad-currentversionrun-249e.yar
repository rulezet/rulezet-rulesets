rule TTP_XOR_QUAD_CurrentVersionRun_249e {
  strings:
    $key_249e = { 77 f1 [2] 53 ff [2] 78 d3 [2] 56 f1 [2] 42 ea [2] 4d f0 [2] 53 ed [2] 51 ec [2] 4a ea [2] 56 ed [2] 4a c2 }

  condition:
    any of them
}