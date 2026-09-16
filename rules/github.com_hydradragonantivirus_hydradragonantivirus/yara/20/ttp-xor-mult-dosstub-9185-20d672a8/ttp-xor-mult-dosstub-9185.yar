rule TTP_XOR_MULT_DOSStub_9185 {
  strings:
    $key_9185 = { c5 ed [2] b1 f5 [2] f6 f7 [2] b1 e6 [2] ff ea [2] f3 e0 [2] e4 eb [2] ff a5 [2] c2 }

  condition:
    any of them
}