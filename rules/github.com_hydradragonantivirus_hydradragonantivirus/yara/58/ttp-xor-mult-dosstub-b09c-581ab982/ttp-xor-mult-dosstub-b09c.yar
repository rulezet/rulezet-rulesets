rule TTP_XOR_MULT_DOSStub_b09c {
  strings:
    $key_b09c = { e4 f4 [2] 90 ec [2] d7 ee [2] 90 ff [2] de f3 [2] d2 f9 [2] c5 f2 [2] de bc [2] e3 }

  condition:
    any of them
}