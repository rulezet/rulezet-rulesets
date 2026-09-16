rule TTP_XOR_MULT_DOSStub_b685 {
  strings:
    $key_b685 = { e2 ed [2] 96 f5 [2] d1 f7 [2] 96 e6 [2] d8 ea [2] d4 e0 [2] c3 eb [2] d8 a5 [2] e5 }

  condition:
    any of them
}