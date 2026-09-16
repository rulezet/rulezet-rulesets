rule TTP_XOR_QUAD_CurrentVersionRun_589e {
  strings:
    $key_589e = { 0b f1 [2] 2f ff [2] 04 d3 [2] 2a f1 [2] 3e ea [2] 31 f0 [2] 2f ed [2] 2d ec [2] 36 ea [2] 2a ed [2] 36 c2 }

  condition:
    any of them
}