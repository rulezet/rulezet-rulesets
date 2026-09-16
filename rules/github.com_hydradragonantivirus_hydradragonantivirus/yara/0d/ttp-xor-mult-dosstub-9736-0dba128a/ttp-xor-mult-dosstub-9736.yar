rule TTP_XOR_MULT_DOSStub_9736 {
  strings:
    $key_9736 = { c3 5e [2] b7 46 [2] f0 44 [2] b7 55 [2] f9 59 [2] f5 53 [2] e2 58 [2] f9 16 [2] c4 }

  condition:
    any of them
}