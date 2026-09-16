rule TTP_XOR_QUAD_CurrentVersionRun_489e {
  strings:
    $key_489e = { 1b f1 [2] 3f ff [2] 14 d3 [2] 3a f1 [2] 2e ea [2] 21 f0 [2] 3f ed [2] 3d ec [2] 26 ea [2] 3a ed [2] 26 c2 }

  condition:
    any of them
}