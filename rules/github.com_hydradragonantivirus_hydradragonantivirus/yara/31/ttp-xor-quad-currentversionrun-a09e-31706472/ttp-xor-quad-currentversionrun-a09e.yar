rule TTP_XOR_QUAD_CurrentVersionRun_a09e {
  strings:
    $key_a09e = { f3 f1 [2] d7 ff [2] fc d3 [2] d2 f1 [2] c6 ea [2] c9 f0 [2] d7 ed [2] d5 ec [2] ce ea [2] d2 ed [2] ce c2 }

  condition:
    any of them
}