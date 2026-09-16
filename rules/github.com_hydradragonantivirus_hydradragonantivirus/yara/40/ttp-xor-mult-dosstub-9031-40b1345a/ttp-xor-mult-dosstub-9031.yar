rule TTP_XOR_MULT_DOSStub_9031 {
  strings:
    $key_9031 = { c4 59 [2] b0 41 [2] f7 43 [2] b0 52 [2] fe 5e [2] f2 54 [2] e5 5f [2] fe 11 [2] c3 }

  condition:
    any of them
}