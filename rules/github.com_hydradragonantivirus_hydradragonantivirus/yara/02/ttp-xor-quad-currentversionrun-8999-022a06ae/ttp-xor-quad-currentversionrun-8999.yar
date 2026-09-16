rule TTP_XOR_QUAD_CurrentVersionRun_8999 {
  strings:
    $key_8999 = { da f6 [2] fe f8 [2] d5 d4 [2] fb f6 [2] ef ed [2] e0 f7 [2] fe ea [2] fc eb [2] e7 ed [2] fb ea [2] e7 c5 }

  condition:
    any of them
}