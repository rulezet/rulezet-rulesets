rule TTP_XOR_MULT_DOSStub_9043 {
  strings:
    $key_9043 = { c4 2b [2] b0 33 [2] f7 31 [2] b0 20 [2] fe 2c [2] f2 26 [2] e5 2d [2] fe 63 [2] c3 }

  condition:
    any of them
}