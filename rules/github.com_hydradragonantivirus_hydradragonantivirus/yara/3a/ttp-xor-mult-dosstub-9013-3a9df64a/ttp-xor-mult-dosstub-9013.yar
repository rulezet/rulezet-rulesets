rule TTP_XOR_MULT_DOSStub_9013 {
  strings:
    $key_9013 = { c4 7b [2] b0 63 [2] f7 61 [2] b0 70 [2] fe 7c [2] f2 76 [2] e5 7d [2] fe 33 [2] c3 }

  condition:
    any of them
}