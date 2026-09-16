rule TTP_XOR_MULT_DOSStub_9620 {
  strings:
    $key_9620 = { c2 48 [2] b6 50 [2] f1 52 [2] b6 43 [2] f8 4f [2] f4 45 [2] e3 4e [2] f8 00 [2] c5 }

  condition:
    any of them
}