rule TTP_XOR_MULT_DOSStub_9485 {
  strings:
    $key_9485 = { c0 ed [2] b4 f5 [2] f3 f7 [2] b4 e6 [2] fa ea [2] f6 e0 [2] e1 eb [2] fa a5 [2] c7 }

  condition:
    any of them
}