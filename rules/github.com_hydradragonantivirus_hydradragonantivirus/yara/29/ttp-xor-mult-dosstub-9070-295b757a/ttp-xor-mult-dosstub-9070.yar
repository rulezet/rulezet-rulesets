rule TTP_XOR_MULT_DOSStub_9070 {
  strings:
    $key_9070 = { c4 18 [2] b0 00 [2] f7 02 [2] b0 13 [2] fe 1f [2] f2 15 [2] e5 1e [2] fe 50 [2] c3 }

  condition:
    any of them
}