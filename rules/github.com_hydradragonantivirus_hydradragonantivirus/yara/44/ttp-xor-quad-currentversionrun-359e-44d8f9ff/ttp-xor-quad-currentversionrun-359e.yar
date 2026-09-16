rule TTP_XOR_QUAD_CurrentVersionRun_359e {
  strings:
    $key_359e = { 66 f1 [2] 42 ff [2] 69 d3 [2] 47 f1 [2] 53 ea [2] 5c f0 [2] 42 ed [2] 40 ec [2] 5b ea [2] 47 ed [2] 5b c2 }

  condition:
    any of them
}