rule TTP_XOR_QUAD_CurrentVersionRun_379e {
  strings:
    $key_379e = { 64 f1 [2] 40 ff [2] 6b d3 [2] 45 f1 [2] 51 ea [2] 5e f0 [2] 40 ed [2] 42 ec [2] 59 ea [2] 45 ed [2] 59 c2 }

  condition:
    any of them
}