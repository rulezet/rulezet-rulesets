rule TTP_XOR_QUAD_CurrentVersionRun_0a9e {
  strings:
    $key_0a9e = { 59 f1 [2] 7d ff [2] 56 d3 [2] 78 f1 [2] 6c ea [2] 63 f0 [2] 7d ed [2] 7f ec [2] 64 ea [2] 78 ed [2] 64 c2 }

  condition:
    any of them
}