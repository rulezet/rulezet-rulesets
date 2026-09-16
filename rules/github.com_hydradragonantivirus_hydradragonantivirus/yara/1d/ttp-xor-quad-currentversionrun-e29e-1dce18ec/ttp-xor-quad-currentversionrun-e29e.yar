rule TTP_XOR_QUAD_CurrentVersionRun_e29e {
  strings:
    $key_e29e = { b1 f1 [2] 95 ff [2] be d3 [2] 90 f1 [2] 84 ea [2] 8b f0 [2] 95 ed [2] 97 ec [2] 8c ea [2] 90 ed [2] 8c c2 }

  condition:
    any of them
}