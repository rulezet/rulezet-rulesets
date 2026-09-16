rule TTP_XOR_MULT_DOSStub_9606 {
  strings:
    $key_9606 = { c2 6e [2] b6 76 [2] f1 74 [2] b6 65 [2] f8 69 [2] f4 63 [2] e3 68 [2] f8 26 [2] c5 }

  condition:
    any of them
}