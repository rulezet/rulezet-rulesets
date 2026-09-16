rule TTP_XOR_MULT_DOSStub_9060 {
  strings:
    $key_9060 = { c4 08 [2] b0 10 [2] f7 12 [2] b0 03 [2] fe 0f [2] f2 05 [2] e5 0e [2] fe 40 [2] c3 }

  condition:
    any of them
}