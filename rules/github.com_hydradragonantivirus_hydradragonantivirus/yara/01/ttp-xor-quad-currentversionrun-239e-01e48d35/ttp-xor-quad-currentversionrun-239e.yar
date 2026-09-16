rule TTP_XOR_QUAD_CurrentVersionRun_239e {
  strings:
    $key_239e = { 70 f1 [2] 54 ff [2] 7f d3 [2] 51 f1 [2] 45 ea [2] 4a f0 [2] 54 ed [2] 56 ec [2] 4d ea [2] 51 ed [2] 4d c2 }

  condition:
    any of them
}