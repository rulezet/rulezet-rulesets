rule TTP_XOR_QUAD_CurrentVersionRun_db9e {
  strings:
    $key_db9e = { 88 f1 [2] ac ff [2] 87 d3 [2] a9 f1 [2] bd ea [2] b2 f0 [2] ac ed [2] ae ec [2] b5 ea [2] a9 ed [2] b5 c2 }

  condition:
    any of them
}