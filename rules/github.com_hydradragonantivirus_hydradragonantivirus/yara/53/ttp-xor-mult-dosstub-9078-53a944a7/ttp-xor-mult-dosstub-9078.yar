rule TTP_XOR_MULT_DOSStub_9078 {
  strings:
    $key_9078 = { c4 10 [2] b0 08 [2] f7 0a [2] b0 1b [2] fe 17 [2] f2 1d [2] e5 16 [2] fe 58 [2] c3 }

  condition:
    any of them
}