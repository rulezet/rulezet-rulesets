rule TTP_XOR_QUAD_CurrentVersionRun_a69e {
  strings:
    $key_a69e = { f5 f1 [2] d1 ff [2] fa d3 [2] d4 f1 [2] c0 ea [2] cf f0 [2] d1 ed [2] d3 ec [2] c8 ea [2] d4 ed [2] c8 c2 }

  condition:
    any of them
}