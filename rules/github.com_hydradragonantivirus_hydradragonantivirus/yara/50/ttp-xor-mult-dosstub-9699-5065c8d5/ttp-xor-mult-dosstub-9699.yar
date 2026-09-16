rule TTP_XOR_MULT_DOSStub_9699 {
  strings:
    $key_9699 = { c2 f1 [2] b6 e9 [2] f1 eb [2] b6 fa [2] f8 f6 [2] f4 fc [2] e3 f7 [2] f8 b9 [2] c5 }

  condition:
    any of them
}