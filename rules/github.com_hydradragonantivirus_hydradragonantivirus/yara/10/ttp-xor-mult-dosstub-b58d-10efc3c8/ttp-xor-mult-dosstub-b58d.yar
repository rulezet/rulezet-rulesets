rule TTP_XOR_MULT_DOSStub_b58d {
  strings:
    $key_b58d = { e1 e5 [2] 95 fd [2] d2 ff [2] 95 ee [2] db e2 [2] d7 e8 [2] c0 e3 [2] db ad [2] e6 }

  condition:
    any of them
}