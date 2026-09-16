rule TTP_XOR_QUAD_CurrentVersionRun_349e {
  strings:
    $key_349e = { 67 f1 [2] 43 ff [2] 68 d3 [2] 46 f1 [2] 52 ea [2] 5d f0 [2] 43 ed [2] 41 ec [2] 5a ea [2] 46 ed [2] 5a c2 }

  condition:
    any of them
}