rule TTP_XOR_MULT_DOSStub_b08d {
  strings:
    $key_b08d = { e4 e5 [2] 90 fd [2] d7 ff [2] 90 ee [2] de e2 [2] d2 e8 [2] c5 e3 [2] de ad [2] e3 }

  condition:
    any of them
}