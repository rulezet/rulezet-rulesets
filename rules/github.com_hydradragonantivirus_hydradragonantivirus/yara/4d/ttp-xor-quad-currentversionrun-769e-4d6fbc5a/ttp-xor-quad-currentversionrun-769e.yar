rule TTP_XOR_QUAD_CurrentVersionRun_769e {
  strings:
    $key_769e = { 25 f1 [2] 01 ff [2] 2a d3 [2] 04 f1 [2] 10 ea [2] 1f f0 [2] 01 ed [2] 03 ec [2] 18 ea [2] 04 ed [2] 18 c2 }

  condition:
    any of them
}