rule TTP_XOR_MULT_DOSStub_9583 {
  strings:
    $key_9583 = { c1 eb [2] b5 f3 [2] f2 f1 [2] b5 e0 [2] fb ec [2] f7 e6 [2] e0 ed [2] fb a3 [2] c6 }

  condition:
    any of them
}