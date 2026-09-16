rule TTP_XOR_MULT_DOSStub_9037 {
  strings:
    $key_9037 = { c4 5f [2] b0 47 [2] f7 45 [2] b0 54 [2] fe 58 [2] f2 52 [2] e5 59 [2] fe 17 [2] c3 }

  condition:
    any of them
}