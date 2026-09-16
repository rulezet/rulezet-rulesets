rule TTP_XOR_MULT_DOSStub_9020 {
  strings:
    $key_9020 = { c4 48 [2] b0 50 [2] f7 52 [2] b0 43 [2] fe 4f [2] f2 45 [2] e5 4e [2] fe 00 [2] c3 }

  condition:
    any of them
}