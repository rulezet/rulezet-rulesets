rule TTP_XOR_MULT_DOSStub_9585 {
  strings:
    $key_9585 = { c1 ed [2] b5 f5 [2] f2 f7 [2] b5 e6 [2] fb ea [2] f7 e0 [2] e0 eb [2] fb a5 [2] c6 }

  condition:
    any of them
}