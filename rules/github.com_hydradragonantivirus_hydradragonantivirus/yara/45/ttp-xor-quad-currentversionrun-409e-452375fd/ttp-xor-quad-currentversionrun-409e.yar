rule TTP_XOR_QUAD_CurrentVersionRun_409e {
  strings:
    $key_409e = { 13 f1 [2] 37 ff [2] 1c d3 [2] 32 f1 [2] 26 ea [2] 29 f0 [2] 37 ed [2] 35 ec [2] 2e ea [2] 32 ed [2] 2e c2 }

  condition:
    any of them
}