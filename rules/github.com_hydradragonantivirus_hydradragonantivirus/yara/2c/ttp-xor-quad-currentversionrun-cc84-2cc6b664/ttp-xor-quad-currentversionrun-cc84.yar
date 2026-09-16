rule TTP_XOR_QUAD_CurrentVersionRun_cc84 {
  strings:
    $key_cc84 = { 9f eb [2] bb e5 [2] 90 c9 [2] be eb [2] aa f0 [2] a5 ea [2] bb f7 [2] b9 f6 [2] a2 f0 [2] be f7 [2] a2 d8 }

  condition:
    any of them
}