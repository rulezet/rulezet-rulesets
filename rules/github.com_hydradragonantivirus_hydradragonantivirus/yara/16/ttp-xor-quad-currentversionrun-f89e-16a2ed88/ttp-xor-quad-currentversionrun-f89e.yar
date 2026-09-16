rule TTP_XOR_QUAD_CurrentVersionRun_f89e {
  strings:
    $key_f89e = { ab f1 [2] 8f ff [2] a4 d3 [2] 8a f1 [2] 9e ea [2] 91 f0 [2] 8f ed [2] 8d ec [2] 96 ea [2] 8a ed [2] 96 c2 }

  condition:
    any of them
}