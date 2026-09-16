rule TTP_XOR_QUAD_CurrentVersionRun_339e {
  strings:
    $key_339e = { 60 f1 [2] 44 ff [2] 6f d3 [2] 41 f1 [2] 55 ea [2] 5a f0 [2] 44 ed [2] 46 ec [2] 5d ea [2] 41 ed [2] 5d c2 }

  condition:
    any of them
}