rule TTP_XOR_MULT_DOSStub_8585 {
  strings:
    $key_8585 = { d1 ed [2] a5 f5 [2] e2 f7 [2] a5 e6 [2] eb ea [2] e7 e0 [2] f0 eb [2] eb a5 [2] d6 }

  condition:
    any of them
}