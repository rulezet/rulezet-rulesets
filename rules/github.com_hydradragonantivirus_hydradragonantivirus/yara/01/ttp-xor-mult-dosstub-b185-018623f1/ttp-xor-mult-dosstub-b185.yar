rule TTP_XOR_MULT_DOSStub_b185 {
  strings:
    $key_b185 = { e5 ed [2] 91 f5 [2] d6 f7 [2] 91 e6 [2] df ea [2] d3 e0 [2] c4 eb [2] df a5 [2] e2 }

  condition:
    any of them
}