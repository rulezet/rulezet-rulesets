rule TTP_XOR_MULT_DOSStub_9092 {
  strings:
    $key_9092 = { c4 fa [2] b0 e2 [2] f7 e0 [2] b0 f1 [2] fe fd [2] f2 f7 [2] e5 fc [2] fe b2 [2] c3 }

  condition:
    any of them
}