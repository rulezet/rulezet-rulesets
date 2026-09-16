rule TTP_XOR_QUAD_CurrentVersionRun_089e {
  strings:
    $key_089e = { 5b f1 [2] 7f ff [2] 54 d3 [2] 7a f1 [2] 6e ea [2] 61 f0 [2] 7f ed [2] 7d ec [2] 66 ea [2] 7a ed [2] 66 c2 }

  condition:
    any of them
}