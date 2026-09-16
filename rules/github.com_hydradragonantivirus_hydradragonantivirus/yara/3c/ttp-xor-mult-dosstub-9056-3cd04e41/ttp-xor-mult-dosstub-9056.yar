rule TTP_XOR_MULT_DOSStub_9056 {
  strings:
    $key_9056 = { c4 3e [2] b0 26 [2] f7 24 [2] b0 35 [2] fe 39 [2] f2 33 [2] e5 38 [2] fe 76 [2] c3 }

  condition:
    any of them
}