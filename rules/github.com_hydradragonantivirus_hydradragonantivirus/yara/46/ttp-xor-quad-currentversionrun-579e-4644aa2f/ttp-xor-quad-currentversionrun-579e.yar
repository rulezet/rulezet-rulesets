rule TTP_XOR_QUAD_CurrentVersionRun_579e {
  strings:
    $key_579e = { 04 f1 [2] 20 ff [2] 0b d3 [2] 25 f1 [2] 31 ea [2] 3e f0 [2] 20 ed [2] 22 ec [2] 39 ea [2] 25 ed [2] 39 c2 }

  condition:
    any of them
}