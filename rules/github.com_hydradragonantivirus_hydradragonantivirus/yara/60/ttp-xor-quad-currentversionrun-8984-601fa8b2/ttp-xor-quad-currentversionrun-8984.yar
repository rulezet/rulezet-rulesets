rule TTP_XOR_QUAD_CurrentVersionRun_8984 {
  strings:
    $key_8984 = { da eb [2] fe e5 [2] d5 c9 [2] fb eb [2] ef f0 [2] e0 ea [2] fe f7 [2] fc f6 [2] e7 f0 [2] fb f7 [2] e7 d8 }

  condition:
    any of them
}