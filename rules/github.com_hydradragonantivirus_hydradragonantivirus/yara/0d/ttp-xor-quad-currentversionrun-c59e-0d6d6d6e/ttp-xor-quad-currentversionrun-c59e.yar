rule TTP_XOR_QUAD_CurrentVersionRun_c59e {
  strings:
    $key_c59e = { 96 f1 [2] b2 ff [2] 99 d3 [2] b7 f1 [2] a3 ea [2] ac f0 [2] b2 ed [2] b0 ec [2] ab ea [2] b7 ed [2] ab c2 }

  condition:
    any of them
}