rule TTP_XOR_MULT_DOSStub_9600 {
  strings:
    $key_9600 = { c2 68 [2] b6 70 [2] f1 72 [2] b6 63 [2] f8 6f [2] f4 65 [2] e3 6e [2] f8 20 [2] c5 }

  condition:
    any of them
}