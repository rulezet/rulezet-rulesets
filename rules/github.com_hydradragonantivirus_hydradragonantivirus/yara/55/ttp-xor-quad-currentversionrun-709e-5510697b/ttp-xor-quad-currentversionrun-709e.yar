rule TTP_XOR_QUAD_CurrentVersionRun_709e {
  strings:
    $key_709e = { 23 f1 [2] 07 ff [2] 2c d3 [2] 02 f1 [2] 16 ea [2] 19 f0 [2] 07 ed [2] 05 ec [2] 1e ea [2] 02 ed [2] 1e c2 }

  condition:
    any of them
}