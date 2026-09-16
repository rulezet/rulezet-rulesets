rule TTP_XOR_MULT_DOSStub_b090 {
  strings:
    $key_b090 = { e4 f8 [2] 90 e0 [2] d7 e2 [2] 90 f3 [2] de ff [2] d2 f5 [2] c5 fe [2] de b0 [2] e3 }

  condition:
    any of them
}