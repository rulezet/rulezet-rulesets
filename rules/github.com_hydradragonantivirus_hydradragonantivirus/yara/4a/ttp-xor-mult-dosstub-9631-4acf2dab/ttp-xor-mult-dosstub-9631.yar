rule TTP_XOR_MULT_DOSStub_9631 {
  strings:
    $key_9631 = { c2 59 [2] b6 41 [2] f1 43 [2] b6 52 [2] f8 5e [2] f4 54 [2] e3 5f [2] f8 11 [2] c5 }

  condition:
    any of them
}