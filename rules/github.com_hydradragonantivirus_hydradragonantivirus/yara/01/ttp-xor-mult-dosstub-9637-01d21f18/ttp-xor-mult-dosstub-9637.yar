rule TTP_XOR_MULT_DOSStub_9637 {
  strings:
    $key_9637 = { c2 5f [2] b6 47 [2] f1 45 [2] b6 54 [2] f8 58 [2] f4 52 [2] e3 59 [2] f8 17 [2] c5 }

  condition:
    any of them
}