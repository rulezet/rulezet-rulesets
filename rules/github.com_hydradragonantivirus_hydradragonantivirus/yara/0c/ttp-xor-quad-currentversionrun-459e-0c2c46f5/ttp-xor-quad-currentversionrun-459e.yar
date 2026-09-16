rule TTP_XOR_QUAD_CurrentVersionRun_459e {
  strings:
    $key_459e = { 16 f1 [2] 32 ff [2] 19 d3 [2] 37 f1 [2] 23 ea [2] 2c f0 [2] 32 ed [2] 30 ec [2] 2b ea [2] 37 ed [2] 2b c2 }

  condition:
    any of them
}