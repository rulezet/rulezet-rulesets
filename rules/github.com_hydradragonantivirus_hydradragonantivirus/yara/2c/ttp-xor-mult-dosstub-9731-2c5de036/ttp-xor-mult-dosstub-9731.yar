rule TTP_XOR_MULT_DOSStub_9731 {
  strings:
    $key_9731 = { c3 59 [2] b7 41 [2] f0 43 [2] b7 52 [2] f9 5e [2] f5 54 [2] e2 5f [2] f9 11 [2] c4 }

  condition:
    any of them
}