rule TTP_XOR_MULT_DOSStub_9388 {
  strings:
    $key_9388 = { c7 e0 [2] b3 f8 [2] f4 fa [2] b3 eb [2] fd e7 [2] f1 ed [2] e6 e6 [2] fd a8 [2] c0 }

  condition:
    any of them
}