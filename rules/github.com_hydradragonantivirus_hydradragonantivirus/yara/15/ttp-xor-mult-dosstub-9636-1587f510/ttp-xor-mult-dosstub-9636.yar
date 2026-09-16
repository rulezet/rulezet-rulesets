rule TTP_XOR_MULT_DOSStub_9636 {
  strings:
    $key_9636 = { c2 5e [2] b6 46 [2] f1 44 [2] b6 55 [2] f8 59 [2] f4 53 [2] e3 58 [2] f8 16 [2] c5 }

  condition:
    any of them
}