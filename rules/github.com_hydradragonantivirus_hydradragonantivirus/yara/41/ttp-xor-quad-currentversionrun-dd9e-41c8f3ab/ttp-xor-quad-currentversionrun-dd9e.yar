rule TTP_XOR_QUAD_CurrentVersionRun_dd9e {
  strings:
    $key_dd9e = { 8e f1 [2] aa ff [2] 81 d3 [2] af f1 [2] bb ea [2] b4 f0 [2] aa ed [2] a8 ec [2] b3 ea [2] af ed [2] b3 c2 }

  condition:
    any of them
}