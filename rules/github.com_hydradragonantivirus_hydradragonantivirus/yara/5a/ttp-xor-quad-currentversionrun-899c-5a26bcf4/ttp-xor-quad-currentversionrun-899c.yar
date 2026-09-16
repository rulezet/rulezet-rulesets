rule TTP_XOR_QUAD_CurrentVersionRun_899c {
  strings:
    $key_899c = { da f3 [2] fe fd [2] d5 d1 [2] fb f3 [2] ef e8 [2] e0 f2 [2] fe ef [2] fc ee [2] e7 e8 [2] fb ef [2] e7 c0 }

  condition:
    any of them
}