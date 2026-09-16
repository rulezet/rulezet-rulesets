rule TTP_XOR_MULT_DOSStub_9399 {
  strings:
    $key_9399 = { c7 f1 [2] b3 e9 [2] f4 eb [2] b3 fa [2] fd f6 [2] f1 fc [2] e6 f7 [2] fd b9 [2] c0 }

  condition:
    any of them
}