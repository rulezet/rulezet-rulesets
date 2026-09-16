rule TTP_XOR_QUAD_CurrentVersionRun_259e {
  strings:
    $key_259e = { 76 f1 [2] 52 ff [2] 79 d3 [2] 57 f1 [2] 43 ea [2] 4c f0 [2] 52 ed [2] 50 ec [2] 4b ea [2] 57 ed [2] 4b c2 }

  condition:
    any of them
}