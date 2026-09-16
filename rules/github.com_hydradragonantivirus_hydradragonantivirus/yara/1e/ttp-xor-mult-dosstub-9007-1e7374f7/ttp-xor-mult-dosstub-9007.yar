rule TTP_XOR_MULT_DOSStub_9007 {
  strings:
    $key_9007 = { c4 6f [2] b0 77 [2] f7 75 [2] b0 64 [2] fe 68 [2] f2 62 [2] e5 69 [2] fe 27 [2] c3 }

  condition:
    any of them
}