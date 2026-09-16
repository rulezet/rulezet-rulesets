rule TTP_XOR_QUAD_CurrentVersionRun_739e {
  strings:
    $key_739e = { 20 f1 [2] 04 ff [2] 2f d3 [2] 01 f1 [2] 15 ea [2] 1a f0 [2] 04 ed [2] 06 ec [2] 1d ea [2] 01 ed [2] 1d c2 }

  condition:
    any of them
}