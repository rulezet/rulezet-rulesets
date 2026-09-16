rule TTP_XOR_MULT_DOSStub_9027 {
  strings:
    $key_9027 = { c4 4f [2] b0 57 [2] f7 55 [2] b0 44 [2] fe 48 [2] f2 42 [2] e5 49 [2] fe 07 [2] c3 }

  condition:
    any of them
}