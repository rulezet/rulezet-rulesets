rule TTP_XOR_MULT_DOSStub_9099 {
  strings:
    $key_9099 = { c4 f1 [2] b0 e9 [2] f7 eb [2] b0 fa [2] fe f6 [2] f2 fc [2] e5 f7 [2] fe b9 [2] c3 }

  condition:
    any of them
}