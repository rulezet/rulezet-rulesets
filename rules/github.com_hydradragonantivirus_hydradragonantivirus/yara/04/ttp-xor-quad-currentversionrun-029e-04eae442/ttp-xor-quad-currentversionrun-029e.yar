rule TTP_XOR_QUAD_CurrentVersionRun_029e {
  strings:
    $key_029e = { 51 f1 [2] 75 ff [2] 5e d3 [2] 70 f1 [2] 64 ea [2] 6b f0 [2] 75 ed [2] 77 ec [2] 6c ea [2] 70 ed [2] 6c c2 }

  condition:
    any of them
}