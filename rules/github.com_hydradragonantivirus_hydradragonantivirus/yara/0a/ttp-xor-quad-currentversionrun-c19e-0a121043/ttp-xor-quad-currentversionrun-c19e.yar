rule TTP_XOR_QUAD_CurrentVersionRun_c19e {
  strings:
    $key_c19e = { 92 f1 [2] b6 ff [2] 9d d3 [2] b3 f1 [2] a7 ea [2] a8 f0 [2] b6 ed [2] b4 ec [2] af ea [2] b3 ed [2] af c2 }

  condition:
    any of them
}