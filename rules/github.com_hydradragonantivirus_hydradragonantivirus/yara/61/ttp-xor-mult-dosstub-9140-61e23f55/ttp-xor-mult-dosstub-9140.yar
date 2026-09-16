rule TTP_XOR_MULT_DOSStub_9140 {
  strings:
    $key_9140 = { c5 28 [2] b1 30 [2] f6 32 [2] b1 23 [2] ff 2f [2] f3 25 [2] e4 2e [2] ff 60 [2] c2 }

  condition:
    any of them
}