rule TTP_XOR_QUAD_CurrentVersionRun_c69e {
  strings:
    $key_c69e = { 95 f1 [2] b1 ff [2] 9a d3 [2] b4 f1 [2] a0 ea [2] af f0 [2] b1 ed [2] b3 ec [2] a8 ea [2] b4 ed [2] a8 c2 }

  condition:
    any of them
}