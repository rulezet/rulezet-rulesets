rule TTP_XOR_QUAD_CurrentVersionRun_899e {
  strings:
    $key_899e = { da f1 [2] fe ff [2] d5 d3 [2] fb f1 [2] ef ea [2] e0 f0 [2] fe ed [2] fc ec [2] e7 ea [2] fb ed [2] e7 c2 }

  condition:
    any of them
}