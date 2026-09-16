rule TTP_XOR_MULT_DOSStub_9617 {
  strings:
    $key_9617 = { c2 7f [2] b6 67 [2] f1 65 [2] b6 74 [2] f8 78 [2] f4 72 [2] e3 79 [2] f8 37 [2] c5 }

  condition:
    any of them
}