rule TTP_XOR_QUAD_CurrentVersionRun_229e {
  strings:
    $key_229e = { 71 f1 [2] 55 ff [2] 7e d3 [2] 50 f1 [2] 44 ea [2] 4b f0 [2] 55 ed [2] 57 ec [2] 4c ea [2] 50 ed [2] 4c c2 }

  condition:
    any of them
}