rule TTP_XOR_MULT_DOSStub_9799 {
  strings:
    $key_9799 = { c3 f1 [2] b7 e9 [2] f0 eb [2] b7 fa [2] f9 f6 [2] f5 fc [2] e2 f7 [2] f9 b9 [2] c4 }

  condition:
    any of them
}