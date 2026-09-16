rule TTP_XOR_QUAD_CurrentVersionRun_e39e {
  strings:
    $key_e39e = { b0 f1 [2] 94 ff [2] bf d3 [2] 91 f1 [2] 85 ea [2] 8a f0 [2] 94 ed [2] 96 ec [2] 8d ea [2] 91 ed [2] 8d c2 }

  condition:
    any of them
}