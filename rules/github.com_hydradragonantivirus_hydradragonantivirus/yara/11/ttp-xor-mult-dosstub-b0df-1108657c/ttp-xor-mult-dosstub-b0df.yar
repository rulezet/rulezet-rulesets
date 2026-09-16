rule TTP_XOR_MULT_DOSStub_b0df {
  strings:
    $key_b0df = { e4 b7 [2] 90 af [2] d7 ad [2] 90 bc [2] de b0 [2] d2 ba [2] c5 b1 [2] de ff [2] e3 }

  condition:
    any of them
}