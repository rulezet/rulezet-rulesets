rule TTP_XOR_QUAD_CurrentVersionRun_329e {
  strings:
    $key_329e = { 61 f1 [2] 45 ff [2] 6e d3 [2] 40 f1 [2] 54 ea [2] 5b f0 [2] 45 ed [2] 47 ec [2] 5c ea [2] 40 ed [2] 5c c2 }

  condition:
    any of them
}