rule TTP_XOR_MULT_DOSStub_9131 {
  strings:
    $key_9131 = { c5 59 [2] b1 41 [2] f6 43 [2] b1 52 [2] ff 5e [2] f3 54 [2] e4 5f [2] ff 11 [2] c2 }

  condition:
    any of them
}