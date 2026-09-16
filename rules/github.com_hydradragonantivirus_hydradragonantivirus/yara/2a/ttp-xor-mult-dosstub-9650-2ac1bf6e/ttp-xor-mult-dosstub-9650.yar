rule TTP_XOR_MULT_DOSStub_9650 {
  strings:
    $key_9650 = { c2 38 [2] b6 20 [2] f1 22 [2] b6 33 [2] f8 3f [2] f4 35 [2] e3 3e [2] f8 70 [2] c5 }

  condition:
    any of them
}