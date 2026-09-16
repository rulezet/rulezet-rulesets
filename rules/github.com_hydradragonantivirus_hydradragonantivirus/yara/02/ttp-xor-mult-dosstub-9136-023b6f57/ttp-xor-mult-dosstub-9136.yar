rule TTP_XOR_MULT_DOSStub_9136 {
  strings:
    $key_9136 = { c5 5e [2] b1 46 [2] f6 44 [2] b1 55 [2] ff 59 [2] f3 53 [2] e4 58 [2] ff 16 [2] c2 }

  condition:
    any of them
}