rule TTP_XOR_MULT_DOSStub_b085 {
  strings:
    $key_b085 = { e4 ed [2] 90 f5 [2] d7 f7 [2] 90 e6 [2] de ea [2] d2 e0 [2] c5 eb [2] de a5 [2] e3 }

  condition:
    any of them
}