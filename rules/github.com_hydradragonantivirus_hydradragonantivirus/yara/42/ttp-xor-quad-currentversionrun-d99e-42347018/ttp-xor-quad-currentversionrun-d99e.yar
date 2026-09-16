rule TTP_XOR_QUAD_CurrentVersionRun_d99e {
  strings:
    $key_d99e = { 8a f1 [2] ae ff [2] 85 d3 [2] ab f1 [2] bf ea [2] b0 f0 [2] ae ed [2] ac ec [2] b7 ea [2] ab ed [2] b7 c2 }

  condition:
    any of them
}