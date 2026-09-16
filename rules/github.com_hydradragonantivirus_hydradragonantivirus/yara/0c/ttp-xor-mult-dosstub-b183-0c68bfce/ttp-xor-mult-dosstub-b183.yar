rule TTP_XOR_MULT_DOSStub_b183 {
  strings:
    $key_b183 = { e5 eb [2] 91 f3 [2] d6 f1 [2] 91 e0 [2] df ec [2] d3 e6 [2] c4 ed [2] df a3 [2] e2 }

  condition:
    any of them
}